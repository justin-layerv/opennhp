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
// The gate's wire shape: an unauthorized request hits the
// plugin's silentDrop path, which Hijacks the connection and
// closes it after writing `Connection: close` with no body. The
// Go HTTP client surfaces this as a wrapped io.EOF.
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
// Reachability assumption: this test runs from the public
// internet (GitHub Actions runner or operator laptop) and
// expects the SYN to reach Traefik on port 443. The AC's L3
// iptables OpenTime clamp gates the BACKEND-target subnet, not
// the public-facing `*.qurl.site:443` listener — the NLB →
// Traefik path on 443 is open to the world by design, with L7
// authz on top. The L3 clamp is what scopes `session_duration`
// against the backend; the L7 gate is what this test
// exercises. (i.e., on this branch the L7 gate is the SOLE
// enforcement layer at the AC's edge — there's no L3 fallback.)
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
	"io"
	"net"
	"net/http"
	"strings"
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
	// the test would otherwise fail with a misleading "no such
	// host" error masquerading as a silentDrop failure mode.
	// 5s timeout absorbs cold-resolve latency on CI runners
	// without flaking on contention.
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dnsCancel()
	if _, err := net.DefaultResolver.LookupHost(dnsCtx, host); err != nil {
		t.Fatalf("DNS for %s did not resolve: %v — confirm wildcard A/AAAA record on the env's QURLSiteDomain", host, err)
	}

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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
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
			resp.StatusCode, body)
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
	// We deliberately do NOT accept "connection reset by peer" (TCP
	// RST) as a silentDrop signal — RST is a different kernel-level
	// shape that can come from NLB backend drain during AC refresh,
	// an SG change racing the test, or an AC crash (segfault /
	// OOMKill). Treating RST as "gate working" would false-pass
	// those degraded-AC scenarios.
	//
	// TLS-layer errors (`tls:`, `x509:`) are rejected: a cert
	// rotation failure can drop the connection after a handshake
	// failure, but that's an AC-cert-health bug, not a gate signal,
	// and we want it to fail loudly so the operator can triage.
	//
	// context.DeadlineExceeded is also rejected — the 15s budget is
	// generous, so a timeout indicates AC or qurl-service latency
	// regression, not a silentDrop signal. Distinguishing prevents
	// the operator from misreading a slow-path bug as a gate
	// regression.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("test deadline (15s) fired before silentDrop manifested: %v — check AC and qurl-service latency, or raise the deadline", err)
	}
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		t.Fatalf("TLS-layer failure, not a silentDrop signal: %v — check AC cert health", err)
	}
	t.Fatalf("expected silentDrop (wrapped io.EOF or io.ErrUnexpectedEOF), got: %v", err)
}
