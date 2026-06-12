//go:build smoke

package smoke

// Tier 2: qurl-router L7 per-session authz gate on *.qurl.site.
//
// Capability shipped in nhp #1984 + traefik-plugins #146 +
// qurl-service #514. Pre-#146 the *.qurl.site branch in the
// qurl-router plugin proxied unconditionally — a session that
// had expired by `session_duration` could refresh the protected
// page indefinitely because there was no L7 enforcement on the
// resource branch (the custom-domain branch already had a gate).
// The L3 OpenTime clamp at iptables enforced session_duration at
// the network layer; the L7 gate is the consumer-cache layer.
//
// The gate's wire shape: an unauthorized request completes TLS,
// hits the plugin's silentDrop path, then the plugin Hijacks the
// connection and closes it after writing `Connection: close` with
// no body. The Go HTTP client surfaces this as a wrapped io.EOF.
//
// This file fences a regression that turns off the gate
// (`enable_qurl_site_authz = false` in tfvars, or a TF refactor
// that drops the `enableQurlSiteAuthz` line from
// `terraform/modules/ac/user_data.sh.tpl`'s rendered Traefik
// plugin config). Either failure mode would make the *.qurl.site
// branch fall through to `proxyRequest` and serve a 4xx/5xx from
// the target-lookup miss instead of silentDropping — the
// assertion below catches both shapes.
//
// Ordering dependency: this test requires the AC ASG refresh
// after the `enable_qurl_site_authz` tfvars flip to have
// completed. `terraform apply` only bumps the AC launch-template
// (the AC ASG has no `instance_refresh{}` block on purpose) so
// existing instances keep their pre-flip plugin config until
// they're replaced. The CI workflow currently fences this
// ordering via job dependencies in `build-and-push.yml`:
// `nhp-smoke-sandbox` depends on `deploy-sandbox-validate`, which
// depends on `deploy-sandbox-blue-green`. A future workflow
// refactor that runs smoke before the refresh would produce a
// confusing red build here.
//
// Reachability assumption: the AC's L3 iptables OpenTime clamp
// drops public `*.qurl.site:443` SYNs until the client has resolved
// a valid qURL through NHP's `/plugins/qurl` handler. The source of
// truth is `terraform/modules/ac/user_data.sh.tpl`: `defaultset` is
// `hash:ip,port,ip`, IPv4 INPUT is restored with default policy DROP,
// and the only public ACCEPT path is a `defaultset`/`tempset` match.
// That successful resolve opens the AC `defaultset` entry for the
// smoke runner's source IP on public 443; it is not scoped to the
// resolved target URL or that target's backend subnet. The precondition
// target is the LayerV-owned NHP /health/live endpoint so a future
// target-reachability validator checks an env-owned URL rather than a
// third-party domain. The assertion request below deliberately sends no
// session cookie, so once the L3 precondition is satisfied the L7
// qurl-router authz gate is the layer under test. If qurl-router ever treats
// a live L3 session/source IP as authorization without the cookie, this test
// fails loudly by receiving an HTTP response instead of silentDrop.
// This intentionally retires the pre-#1989 assumption that 443 was
// globally reachable and the qurl-router gate was the only edge
// enforcement layer. If the AC firewall model changes back to globally
// reachable public 443, the resolve step becomes unnecessary coupling;
// update this test at the same time so it does not depend on qURL
// mint/resolve health when the L7 gate can be reached directly.
//
// Asymmetry with the positive path: this test catches
// "gate accidentally disabled" but NOT the inverse "gate
// enabled + fail-closed bug" (the gate denies even authorized
// sessions). The positive-path Tier 2 companion is tracked in
// follow-up issue #1985; until that lands, the long-session
// regression check in the PR rollout runbook is the manual
// fence.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// qurlSiteAuthzOptOutEnvs marks environments where
// `enable_qurl_site_authz` is intentionally false (rollback, or a
// greenfield env still in pre-flip burn-in). Empty by default.
// Mirrors the pattern in `09_public_alb_internal_lockdown_test.go`'s
// `httpListenerOptOutEnvs`. CLAUDE.md #1640 tracks consolidating
// these env-keyed gates onto SSM-sourced reads; until that lands,
// adding a new env that opts out is a one-line edit here.
//
// ROLLBACK COORDINATION: a tfvars flip back to
// `enable_qurl_site_authz = false` (with the corresponding AC
// refresh) requires adding the env to this map in the same change.
// Otherwise the test would surface a misleading silentDrop-missing
// failure on the post-rollback run rather than a clean skip. The
// other four lockstep sites listed in CLAUDE.md's smoke section
// have the same shape.
var qurlSiteAuthzOptOutEnvs = map[string]bool{}

const (
	qurlAuthzGateL3PreconditionFailureContext = "L3 precondition for qurl-router authz smoke"

	// Do not reuse resolveRetryBudget here. resolveWithRetries may spend
	// 45s across fresh qURL mints while blue/green settles, but once it
	// returns the /plugins/qurl handler's NHP knock callback has already
	// succeeded. The remaining wait only covers public NLB/iptables
	// propagation to the no-cookie probe.
	silentDropProbeBudget = 15 * time.Second
	// A healthy qurl-router silentDrop hijacks and closes immediately after
	// TLS/request handling, so 5s is intentionally a fail-loud ceiling once the
	// attempt trace proves the probe reached TCP/TLS. Pre-connection timeouts
	// still retry within silentDropProbeBudget as L3 pinhole propagation. Keep
	// this explicit instead of aliasing resolvePerAttemptTimeout so future
	// resolve tuning does not silently soften or harden the authz-gate signal.
	silentDropProbePerAttemptTimeout = 5 * time.Second
	// Avoid launching a final sub-second probe that only overwrites lastErr with
	// a self-inflicted context timeout. The previous full/near-full timeout is a
	// better triage signal once the hard wall-clock budget is effectively spent.
	silentDropProbeMinAttemptTimeout = 1 * time.Second
	// Separate from postFlipPollInterval: this waits for already-authorized
	// public NLB/iptables propagation, not blue/green color convergence. Keep it
	// short enough that the 15s budget still gets two-to-three dropped-SYN
	// attempts.
	silentDropProbePollInterval = 1 * time.Second
)

// TestQurlRouterAuthzGate_SilentDropsUnauthenticatedRequests
// asserts that a request to *.qurl.site with no session cookie
// and no XFF terminates without an HTTP response. The resource ID
// is randomly-shaped and not registered in DDB; the plugin's gate
// fires BEFORE the target-lookup miss, so the absence of a real
// DDB row doesn't short-circuit the test.
func TestQurlRouterAuthzGate_SilentDropsUnauthenticatedRequests(t *testing.T) {
	if testConfig.QURLSiteDomain == "" {
		t.Skip("QURL site domain not configured in smoke testConfig")
	}
	if qurlSiteAuthzOptOutEnvs[testConfig.Environment] {
		t.Skipf("enable_qurl_site_authz disabled in env %q (see qurlSiteAuthzOptOutEnvs)", testConfig.Environment)
	}

	// Synthetic resource ID. r_smokeprobe1 is the known-synthetic
	// identifier this repo uses for "absolutely not a real
	// resource" probes; ssm_probe.go's cmdCurlInternalQurlAPIFmt
	// and qurlServiceInternalProbePath() both reference it, and
	// if a future plugin tightens its resource-ID validator (e.g.,
	// minimum length — r_smokeprobe1 is 11 chars post-prefix vs.
	// production's ~20) all three sites need to move to a longer
	// synthetic ID together.
	//
	// Provision-collision shape: if an operator ever provisions a
	// real qURL with id `r_smokeprobe1`, this test's silentDrop
	// assertion still holds — the test sends NO session cookies,
	// so even a real resource's authz call returns deny (no
	// active session for the test runner's IP) and the plugin
	// silentDrops. The behavior change is on ssm_probe.go's
	// `/target` probe (a real resource would return the record
	// instead of 404). The test's failure mode is independent
	// of the collision.
	//
	// (Variable named `targetURL` rather than `url` to avoid
	// shadowing the `net/url` package name in case a future edit
	// imports it.)
	host := "r_smokeprobe1." + testConfig.QURLSiteDomain
	targetURL := "https://" + host + "/"

	// DNS pre-check. Wildcard DNS for *.qurl.site is owned by
	// the env's qurl_site_domain TF resource; if it's missing
	// the test would otherwise mint and consume a single-use qURL
	// before failing with a misleading "no such host" error
	// masquerading as a silentDrop failure mode. 5s timeout absorbs
	// cold-resolve latency on CI runners without flaking on contention.
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dnsCancel()
	if _, err := net.DefaultResolver.LookupHost(dnsCtx, host); err != nil {
		t.Fatalf("DNS for %s did not resolve: %v — confirm wildcard A/AAAA record on the env's QURLSiteDomain", host, err)
	}

	// Establish the L3 precondition first. The AC host firewall drops
	// public 443 until a valid NHP qurl resolve opens defaultset for this
	// runner's source IP. This necessarily couples the authz-gate fence
	// to Auth0 M2M + qurl-service mint/resolve health; failures before
	// this point should be triaged as precondition failures, not as direct
	// evidence that the qurl-router authz gate regressed. We intentionally
	// ignore the 302 response and build the assertion request with a fresh
	// cookie-jar-less client below, so the request under assertion remains an
	// unauthenticated L7 request.
	//
	// Preconditions and side effects are intentionally explicit:
	// - OpenTime/session_duration must stay comfortably above
	//   silentDropProbeBudget. Sandbox and prod qurl-service defaults are 300s;
	//   tuning them near this post-resolve probe window creates a
	//   pinhole-expiry race.
	// - The NHP resolve request and AC *.qurl.site probe must share one runner
	//   egress IP. A multi-IP NAT pool could open defaultset for one source IP
	//   and probe from another.
	// - AC defaultset is assumed to be scoped by source IP/protocol/port, not by
	//   resolved host or target. If pinholes ever become target-scoped, the
	//   resolve target and probe target must move in lockstep.
	// - A blue/green flip after resolve can strand the pinhole on the old AC
	//   fleet; timeout failures below include that triage path.
	// - resolveWithRetries mints a fresh single-use qURL on each retry and
	//   registers cleanup on this parent test, so blue/green churn can create
	//   several cleanup callbacks without orphaning smoke resources.
	// - The runner-IP pinhole stays open for the rest of the OpenTime window; no
	//   later smoke test should assert L3-closed behavior from the same runner
	//   IP without ordering or egress isolation.
	ctx := context.Background()
	preconditionTargetURL := testConfig.NHPServerBaseURL + "/health/live"
	t.Logf("L3 precondition: resolving qURL through NHP /plugins/qurl to open AC defaultset for the smoke runner source IP")
	_ = resolveWithRetriesLabeled(ctx, t, func() *QURLResponse {
		return mintSmokeQURLLabeled(ctx, t, preconditionTargetURL, qurlAuthzGateL3PreconditionFailureContext)
	}, qurlAuthzGateL3PreconditionFailureContext)

	// Dedicated client: no keep-alive reuse with prior tests
	// (silentDrop closes the connection — a pooled connection
	// from an earlier test would muddy the failure mode); no
	// redirect follow. Deliberately no `Timeout` field —
	// context.WithTimeout below is the single source of truth
	// for the deadline, so a deadline-fire is always surfaced
	// as context.DeadlineExceeded (handled with a specific
	// failure message). Setting both would race and produce
	// different error shapes depending on which fires first.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// No session cookie / no XFF on this request — the gate's
	// fail-closed path is exactly what we're fencing. Don't
	// "helpfully" set a cookie here; that would test the
	// authorized path, which is tracked separately in #1985.
	//
	// The deadline is the only retry guard here: non-timeout errors fail
	// immediately, while timeout attempts and inter-attempt sleeps are clipped
	// to the remaining budget so silentDropProbeBudget is a hard wall-clock
	// cap even when the last attempt starts near the deadline. Timeout retries
	// are only for attempts that did not reach TLS completion: a dropped SYN is
	// the expected L3 propagation shape, while a TCP-accepting AC target can
	// still drain or stall before Traefik has a TLS session where qurl-router
	// could run. Once TLS completes, a timeout is a qurl-router/Traefik/AC
	// health problem rather than L3 propagation.
	deadline := time.Now().Add(silentDropProbeBudget)
	attempt := 0
	var lastErr error
	for {
		remaining := time.Until(deadline)
		if remaining < silentDropProbeMinAttemptTimeout {
			failSilentDropProbeTimeout(t, lastErr)
		}
		attempt++
		attemptTimeout := silentDropProbePerAttemptTimeout
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}

		reqCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		probeTrace := &silentDropProbeTrace{}
		reqCtx = httptrace.WithClientTrace(reqCtx, probeTrace.clientTrace())
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			cancel()
			t.Fatalf("build request: %v", err)
		}

		resp, err := client.Do(req)
		var body []byte
		var statusCode int
		if err == nil {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 256))
			statusCode = resp.StatusCode
			_ = resp.Body.Close()
		}
		cancel()
		if err == nil {
			t.Fatalf("unauthenticated *.qurl.site request must silentDrop, got HTTP %d body=%q. "+
				"Likely causes: (a) enable_qurl_site_authz flipped back to false in tfvars, "+
				"(b) a TF refactor dropped the enableQurlSiteAuthz line from user_data.sh.tpl's "+
				"rendered Traefik plugin config, (c) the AC ASG hasn't been refreshed since "+
				"the tfvars flip (LT version bumped but instances not replaced — the AC ASG "+
				"has no instance_refresh{} block), (d) a Traefik router-priority change "+
				"reordered *.qurl.site past the qurl-router middleware so the host matches a "+
				"different router and never reaches the plugin, or (e) a plugin refactor "+
				"reordered authz to run AFTER the target lookup, so a synthetic resource ID "+
				"now hits the not-found branch and returns 4xx before the gate runs (HTTP 4xx "+
				"here, not silentDrop). See https://github.com/layervai/traefik-plugins/blob/main/plugins-local/src/github.com/traefik/qurl-router/qurl_router.go for the gate ordering.",
				statusCode, body)
		}

		// silentDrop manifests as a wrapped io.EOF (or io.ErrUnexpectedEOF
		// when the close races mid-response-line): the plugin Hijacks the
		// connection and writes `Connection: close` then closes the
		// socket cleanly (FIN, not RST). The Go HTTP client wraps both
		// EOF variants in a url.Error whose underlying err satisfies
		// errors.Is — no Go-version-specific string-matching fallback
		// is needed on Go 1.21+. (smoke module go.mod is pinned to
		// 1.26.4 today, well past the floor.)
		//
		// The DROP assumption is source-backed by AC user_data's INPUT
		// default-DROP policy and Traefik-start guard that refuses to run
		// unless `iptables -S INPUT` reports `-P INPUT DROP`. A future
		// REJECT-mode firewall migration should update this retry predicate
		// deliberately.
		//
		// A pre-TLS EOF is also not accepted as success: qurl-router runs after
		// Traefik terminates TLS, so a close before that point means the gate did
		// not execute. It is still retryable inside the wall-clock budget because
		// an AC drain / NLB target rotation can close one backend connection while
		// the next fresh connection reaches the healthy fleet. Persistent pre-TLS
		// closes exhaust the budget and fail with the trace state below.
		//
		// We deliberately do NOT accept "connection reset by peer" (TCP
		// RST) as a silentDrop signal — RST is a different kernel-level
		// shape that can come from NLB backend drain during AC refresh,
		// an SG change racing the test, or an AC crash (segfault /
		// OOMKill). Treating RST as "gate working" would false-pass
		// those degraded-AC scenarios. The propagation retry above is
		// intentionally timeout-only because the AC L3 clamp uses DROP
		// before defaultset reaches the runner IP; an RST during this
		// window is not the expected propagation shape and should fail
		// loud rather than be retried as a healthy-but-late pinhole.
		//
		// Timeouts are checked before TLS string matching so a stalled
		// mid-handshake path is triaged as a slow/drop path, not cert health.
		// Non-timeout TLS-layer errors (`tls:`, `x509:`) are rejected: a
		// cert rotation failure can drop the connection after a handshake
		// failure, but that's an AC-cert-health bug, not a gate signal, and
		// we want it to fail loudly so the operator can triage.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			if !probeTrace.tlsHandshakeCompleted.Load() {
				lastErr = fmt.Errorf("connection closed before TLS completed, not a qurl-router silentDrop signal (%s): %w",
					probeTrace.summary(), err)
				if time.Now().Before(deadline) {
					t.Logf("silentDrop probe attempt %d closed before TLS completed; retrying within %s budget: %v",
						attempt, silentDropProbeBudget, lastErr)
					sleepFor := silentDropProbePollInterval
					if sleepRemaining := time.Until(deadline); sleepRemaining < sleepFor {
						sleepFor = sleepRemaining
					}
					if sleepFor > 0 {
						time.Sleep(sleepFor)
					}
					continue
				}
				t.Fatalf("%v — check AC/NLB backend health or drain during refresh", lastErr)
			}
			return
		}
		if isTimeoutError(err) {
			if probeTrace.connectionReached() {
				if !probeTrace.tlsHandshakeCompleted.Load() {
					lastErr = fmt.Errorf("silentDrop probe attempt %d timed out before TLS completed after reaching TCP/TLS (%s): %w",
						attempt, probeTrace.summary(), err)
					if time.Now().Before(deadline) {
						t.Logf("silentDrop probe attempt %d timed out before TLS completed; retrying within %s budget: %v",
							attempt, silentDropProbeBudget, lastErr)
						sleepFor := silentDropProbePollInterval
						if sleepRemaining := time.Until(deadline); sleepRemaining < sleepFor {
							sleepFor = sleepRemaining
						}
						if sleepFor > 0 {
							time.Sleep(sleepFor)
						}
						continue
					}
					failSilentDropProbeTimeout(t, lastErr)
				}
				t.Fatalf("silentDrop probe attempt %d timed out after TLS completed (%s); "+
					"not retrying as L3 pinhole propagation. This usually means the qurl-router/Traefik "+
					"path accepted the connection but failed to produce the expected silentDrop EOF or an "+
					"HTTP response within %s: %v",
					attempt, probeTrace.summary(), attemptTimeout, err)
			}
			if time.Now().Before(deadline) {
				lastErr = err
				t.Logf("silentDrop probe attempt %d timed out while L3 pinhole may still be propagating after resolve: %v", attempt, err)
				sleepFor := silentDropProbePollInterval
				if sleepRemaining := time.Until(deadline); sleepRemaining < sleepFor {
					sleepFor = sleepRemaining
				}
				if sleepFor > 0 {
					time.Sleep(sleepFor)
				}
				continue
			}
			failSilentDropProbeTimeout(t, err)
		}
		errStr := err.Error()
		if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
			t.Fatalf("TLS-layer failure, not a silentDrop signal: %v — check AC cert health", err)
		}
		if lastErr != nil {
			t.Fatalf("expected silentDrop (wrapped io.EOF or io.ErrUnexpectedEOF), got: %v (previous timeout while waiting for L3 pinhole: %v)", err, lastErr)
		}
		t.Fatalf("expected silentDrop (wrapped io.EOF or io.ErrUnexpectedEOF), got: %v", err)
	}
}

func failSilentDropProbeTimeout(t *testing.T, err error) {
	t.Helper()
	lastErr := "no request attempt completed before the deadline expired"
	if err != nil {
		lastErr = err.Error()
	}
	t.Fatalf("timed out waiting for silentDrop after opening the L3 pinhole via qurl resolve; last error: %s — check AC ipset propagation, broadcast-to-AC success, qurl-service latency before the runner connection reaches public 443, qurl-service OpenTime/session_duration shorter than the %s probe budget, or runner egress-IP stability",
		lastErr, silentDropProbeBudget)
}

type silentDropProbeTrace struct {
	tcpConnected          atomic.Bool
	gotConn               atomic.Bool
	tlsHandshakeStarted   atomic.Bool
	tlsHandshakeCompleted atomic.Bool
	gotFirstResponseByte  atomic.Bool
}

func (p *silentDropProbeTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				p.tcpConnected.Store(true)
			}
		},
		GotConn: func(httptrace.GotConnInfo) {
			p.gotConn.Store(true)
		},
		TLSHandshakeStart: func() {
			p.tlsHandshakeStarted.Store(true)
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				p.tlsHandshakeCompleted.Store(true)
			}
		},
		GotFirstResponseByte: func() {
			p.gotFirstResponseByte.Store(true)
		},
	}
}

func (p *silentDropProbeTrace) connectionReached() bool {
	return p.tcpConnected.Load() ||
		p.gotConn.Load() ||
		p.tlsHandshakeStarted.Load() ||
		p.tlsHandshakeCompleted.Load() ||
		p.gotFirstResponseByte.Load()
}

func (p *silentDropProbeTrace) summary() string {
	return "tcp_connected=" + strconv.FormatBool(p.tcpConnected.Load()) +
		" got_conn=" + strconv.FormatBool(p.gotConn.Load()) +
		" tls_handshake_started=" + strconv.FormatBool(p.tlsHandshakeStarted.Load()) +
		" tls_handshake_completed=" + strconv.FormatBool(p.tlsHandshakeCompleted.Load()) +
		" got_first_response_byte=" + strconv.FormatBool(p.gotFirstResponseByte.Load())
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
