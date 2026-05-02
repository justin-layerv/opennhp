//go:build smoke

package smoke

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Tier 1 regression fences for the qurl-service /internal/v1/* network
// isolation rollout (qurl-service issue #335 + #299, network-layer fix).
//
// Capability under test: the qurl-service internal ALB (internal=true,
// in workload private subnets) serves /internal/v1/* on
// internal-api.qurl.layerv.{xyz,ai}, which:
//   - is NOT publicly resolvable (workload-account private hosted zone
//     attached only to the workload VPC; no record in the public
//     mgmt-account zone other than the ACM DNS-01 validation CNAME).
//   - resolves to RFC1918 addresses from inside the VPC (NHP server,
//     AC, and any other workload sharing the VPC).
//   - serves traffic via an HTTPS listener with a cert that validates
//     against the internal hostname.
//   - reaches the qurl-service handler stack (HostValidation,
//     IPRateLimiter, InternalServiceAuth) when called from inside the
//     VPC, returning 401 from the auth middleware on unauthenticated
//     calls.
//
// The fences below catch the regression classes that PR1 introduces and
// that subsequent rollout PRs / refactors / IaC drift could re-open:
//   - Public-DNS leak (the A-alias accidentally landing in the public
//     mgmt zone, or the private hosted zone losing its VPC association
//     and DNS resolution falling back to the public zone).
//   - Private hosted zone misconfiguration (zone not attached to the
//     workload VPC; A-alias pointing at a stale ALB ARN; resolver loop).
//   - HostValidation drift (internal hostname dropped from
//     ALLOWED_HOSTS, causing the handler to 400 every internal call).
//   - SG / ALB regression (ECS tasks unreachable from internal ALB,
//     causing 502/504 from the ALB-side health-check failure).
//
// These fences MUST run from both inside the VPC (SSM probes against
// NHP server) and outside (direct DNS lookup from the CI runner). The
// outside-fence is the only one that can detect a public-DNS leak; the
// inside-fences are the only ones that can detect VPC-side breakage.
//
// Regression fence for qurl-service issue #335 (closed via
// layervai/nhp#1588).

// publicResolvers lists the resolvers used by
// TestQurlInternalALB_NotPubliclyResolvable. All must independently
// return NXDOMAIN — single-source NXDOMAIN can mask DNSSEC validation
// errors or one-resolver outages, and a future GitHub-runner egress
// change might block any one of them. Three independent operators
// (Cloudflare, Google, Quad9) is enough to pin "the world cannot
// resolve this hostname" without overdoing it.
var publicResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
}

// TestQurlInternalALB_NotPubliclyResolvable fences the public-DNS-leak
// regression class. The internal ALB hostname must NOT have a public A
// record — only the ACM DNS-01 validation CNAME (under
// `_acme-challenge.internal-api.qurl.*`) lives in the public mgmt
// zone. If a future commit accidentally adds the A-alias to the public
// zone (instead of the workload-account private zone), this test
// catches it on the first CI run from a public-resolver-routed runner.
//
// We use a fresh net.Resolver bound to a public resolver IP rather
// than the GitHub runner's default resolver. The runner's resolver
// could in principle be on a corporate VPN that resolves into our
// private zone (none of ours do today, but the assertion is stronger
// if it explicitly bypasses any in-band resolver). Three independent
// resolvers must agree on NXDOMAIN.
func TestQurlInternalALB_NotPubliclyResolvable(t *testing.T) {
	if !testConfig.QURLInternalALBEnabled {
		t.Skip("NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED not set — internal ALB not yet live in this env (rollout in progress, or rolled back)")
	}

	for _, resolverAddr := range publicResolvers {
		t.Run(resolverAddr, func(t *testing.T) {
			// Three independent resolvers query in parallel — caps wall
			// time at ~10s instead of ~30s and surfaces single-resolver
			// network flakes faster.
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			addr := resolverAddr
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, network, addr)
				},
			}

			addrs, err := resolver.LookupHost(ctx, testConfig.QURLInternalAPIHostname)
			if err == nil {
				t.Fatalf("public resolver %s returned addresses for %s (must NXDOMAIN): %v",
					addr, testConfig.QURLInternalAPIHostname, addrs)
			}

			// Be specific about the error shape — timeouts and SERVFAIL
			// can mask a leaked record behind a flaky resolver path. The
			// contract is IsNotFound (NXDOMAIN), nothing else.
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) {
				t.Fatalf("resolver %s: expected *net.DNSError, got %T: %v", addr, err, err)
			}
			if !dnsErr.IsNotFound {
				t.Fatalf("resolver %s: expected IsNotFound=true (NXDOMAIN), got DNSError{IsNotFound=%v, IsTimeout=%v, IsTemporary=%v, Err=%q}",
					addr, dnsErr.IsNotFound, dnsErr.IsTimeout, dnsErr.IsTemporary, dnsErr.Err)
			}
		})
	}
}

// isPrivateOrCGN returns true when ip is in any RFC1918 range, IPv6
// ULA (fc00::/7), or IPv4 CGN (100.64.0.0/10). LayerV's VPCs use
// RFC1918 today, but AWS hands out 100.64/10 for some greenfield
// VPCs; if a future env lands there, this avoids a misleading
// "non-RFC1918 address" failure that would actually be a correctly-
// configured private VPC.
func isPrivateOrCGN(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		// 100.64.0.0/10 — second octet is 64..127, i.e. top two bits = 01.
		return true
	}
	return false
}

// TestQurlInternalALB_ResolvesToPrivateIPsFromVPC fences the
// private-hosted-zone-and-VPC-association regression class. From any
// EC2 in the workload VPC, the internal ALB hostname must resolve to
// RFC1918 (or AWS CGN) addresses — the ALB's ENIs. If the PHZ loses
// its VPC association or the A-alias breaks, this test fails by
// either an empty `dig +short` output or addresses outside the
// expected private ranges.
//
// Iterates every InService instance in the ASG, not just the first.
// The PHZ-association regression class can manifest as "one instance
// has stale resolver state" — fleet-wide iteration is the only way
// to catch it, mirroring TestKnockLifecycle_AllServersReportACPeers.
func TestQurlInternalALB_ResolvesToPrivateIPsFromVPC(t *testing.T) {
	if !testConfig.QURLInternalALBEnabled {
		t.Skip("NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED not set — internal ALB not yet live in this env (rollout in progress, or rolled back)")
	}
	skipIfNoSSMProbes(t)

	asgName := requireActiveServerASG(t)
	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s — cannot probe DNS from VPC", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	for _, instance := range instances {
		out, err := probeDigInternalQurlAPI(ctx, instance, testConfig.QURLInternalAPIHostname)
		if err != nil {
			t.Errorf("instance %s: dig %s failed: %v", instance, testConfig.QURLInternalAPIHostname, err)
			continue
		}

		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) == 0 || lines[0] == "" {
			t.Errorf("instance %s: dig %s returned empty answer (private hosted zone misconfigured? VPC association dropped?)",
				instance, testConfig.QURLInternalAPIHostname)
			continue
		}

		// `dig +short` on an alias-A record returns A records (not
		// CNAMEs). If a future change makes the record type CNAME,
		// net.ParseIP returns nil and the test fails with a misleading
		// "not an IP address" error — caller would need to inspect
		// `lines[0]` to recognize that. The lifecycle + record-type
		// pinning in main.tf makes this a low-risk class.
		for _, line := range lines {
			ip := net.ParseIP(strings.TrimSpace(line))
			if ip == nil {
				t.Errorf("instance %s: dig output line %q is not an IP address (record type changed from A?)", instance, line)
				continue
			}
			if !isPrivateOrCGN(ip) {
				t.Errorf("instance %s: dig %s returned non-private address %s — private zone may be leaking to public resolver, or A-alias points at the public ALB",
					instance, testConfig.QURLInternalAPIHostname, ip)
			}
		}
	}
}

// TestQurlInternalALB_HandlerReachableFromVPC fences the end-to-end
// stack-reachability regression class for both /internal/v1/* endpoints
// the rollout cares about.
//
// Two parallel probes per instance:
//
//   - GET /internal/v1/resource/r_smokeprobe1/target — used by AC's
//     Traefik plugin in PR3.
//   - POST /internal/v1/resolve with empty JSON body — the actual
//     endpoint named by issue qurl-service#335 and used by NHP plugin
//     in PR2. Probing it directly catches a future refactor that
//     changes middleware order on /resolve specifically (e.g., body
//     parsing before auth).
//
// Both must return 401:
//   - 401 proves DNS resolves, TLS handshakes against the new internal
//     cert, ALB SG accepts the connection, HostValidation accepts the
//     Host header (otherwise 400), and the auth middleware actually
//     runs (otherwise the handler would 404 a missing resource or
//     400 an empty body, masking the auth gate).
//   - 502/504 means the ALB target group is unreachable (SG misconfig
//     between internal-ALB SG and ECS task SG).
//   - 200 would mean the auth middleware was bypassed entirely — far
//     worse regression (anyone in the VPC could call /internal/v1/*).
//
// We deliberately do NOT pass a service token: probe output lands in
// SSM command logs, and reading the token from the instance's env file
// just to send it back widens the blast radius of a log-leak for no
// test signal we don't already have.
//
// Iterates every InService instance to catch per-instance regressions
// (resolver cache drift, TLS trust store skew).
func TestQurlInternalALB_HandlerReachableFromVPC(t *testing.T) {
	if !testConfig.QURLInternalALBEnabled {
		t.Skip("NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED not set — internal ALB not yet live in this env (rollout in progress, or rolled back)")
	}
	skipIfNoSSMProbes(t)

	asgName := requireActiveServerASG(t)
	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s — cannot probe internal ALB", asgName)
	}

	endpoints := []struct {
		name string
		kind internalQurlEndpoint
	}{
		{"resource_target_GET", internalQurlEndpointResourceTarget},
		{"resolve_POST", internalQurlEndpointResolve},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			path := ep.kind.path()
			// Inner subtest per instance with t.Parallel() so an N-instance
			// ASG × 2-endpoint × ~45s SSM-wait grid runs concurrently
			// rather than serially. Same shape as TestKnockLifecycle_*.
			for _, instance := range instances {
				instance := instance // capture before t.Parallel
				t.Run(instance, func(t *testing.T) {
					t.Parallel()

					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					defer cancel()

					code, err := probeCurlInternalQurlEndpointStatus(ctx, instance, testConfig.QURLInternalAPIHostname, ep.kind)
					if errors.Is(err, errCurlNoResponse) {
						t.Errorf("instance %s endpoint %s: TCP timeout / no HTTP response from internal ALB — DNS resolved but the ALB or task SG is dropping the connection", instance, path)
						return
					}
					if err != nil {
						t.Errorf("instance %s: curl https://%s%s failed: %v",
							instance, testConfig.QURLInternalAPIHostname, path, err)
						return
					}

					switch code {
					case http.StatusUnauthorized:
						// Expected — auth middleware reached, no token presented.
					case http.StatusBadRequest:
						// Multiple paths can produce 400, all regressions worth diagnosing:
						// (a) HostValidation rejected (internal hostname missing from
						//     ALLOWED_HOSTS / qurl_additional_allowed_hosts).
						// (b) On /resolve specifically: body parsing ran before auth, so
						//     an empty body produced "invalid_request_body" before the
						//     401. This is the regression class the /resolve probe
						//     exists to catch.
						// (c) On /resource/.../target: a refactor moved resource-ID
						//     format validation above auth.
						t.Errorf("instance %s endpoint %s: got 400 — likely HostValidation rejecting, or middleware-order regression (body/format check moved above auth)", instance, path)
					case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
						t.Errorf("instance %s endpoint %s: got %d — internal-ALB-SG → ECS-task-SG path is broken (target group health checks failing or no targets registered)", instance, path, code)
					default:
						t.Errorf("instance %s endpoint %s: got unexpected status %d; want 401 (auth middleware reached, no token presented)", instance, path, code)
					}
				})
			}
		})
	}
}
