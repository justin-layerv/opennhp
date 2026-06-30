//go:build smoke

package smoke

import "fmt"

// derivedEndpoints holds the default URLs for a given NHP environment.
// Tests and TestMain read these as fallbacks; explicit env vars take
// precedence.
//
// NOTE: NHPServerBaseURL is the nhp-server's NLB endpoint at
// resolve.qurl.link.*, NOT api.layerv.* (which is QURL service).
// /health/* and /plugins/* are served on the NHP server; /v1/* is
// served on the QURL API.
type derivedEndpoints struct {
	NHPServerBaseURL string

	// NHPServerOriginURL is the NLB-direct hostname for the NHP server's
	// HTTPS plugin endpoint, BYPASSING any CloudFront in front of
	// resolve.qurl.link. Used by the keep-alive idle-timeout fence
	// (09_resolve_origin_idle_timeout_test.go) to probe the server
	// directly. Prefer NHPServerBaseURL for any test that wants the
	// production traffic path; this is for tests that specifically need
	// to bypass CF (e.g., to fence server-side timeout behavior, which
	// CF would mask via origin connection pooling and retries).
	NHPServerOriginURL string

	QURLAPIBaseURL string

	// QURLInternalAPIHostname is the qurl-service internal ALB hostname.
	// Empty when the internal ALB is not yet enabled (allowing the new
	// fence tests to skip cleanly in pre-rollout environments).
	QURLInternalAPIHostname string

	// QURLSiteDomain is the parent domain of per-resource qurl.site
	// hostnames. The shape differs by environment: sandbox uses the
	// sub-FQDN `qurl.site.layerv.xyz` (so per-resource hosts are
	// r_{id}.qurl.site.layerv.xyz); prod uses the registered apex
	// `qurl.site` directly (so per-resource hosts are r_{id}.qurl.site).
	// Tier 2 resolve tests assert cookies are scoped to this domain
	// and that the 302 Location host has this as its suffix.
	QURLSiteDomain string

	// QURLLinkOrigin is the origin (scheme + host) of the qurl.link
	// page that the SPA loads from. Tier 2 negotiation tests use it
	// as the Origin header on cross-origin fetch() simulations and
	// assert the server echoes it back in Access-Control-Allow-Origin.
	QURLLinkOrigin string

	// ResolveEndpointEnabled reports whether the nhp-server's HTTP
	// surface (the /health/*, /plugins/*, and qURL token-resolution
	// path) is reachable at NHPServerBaseURL in this env. It mirrors the
	// Terraform local `qurl_resolve_endpoint_enabled = deploy_qurl_link &&
	// !qurl_link_js_agent_enabled` (terraform/main.tf): an env that turns
	// on the browser JS-agent + relay topology (qurl_link_js_agent_enabled
	// = true) tears that public surface down entirely — the resolve /
	// resolve-origin Route53 records and the server NLB HTTPS listener (and
	// its blue/green SSM params) are not created. Tests that hit
	// resolve.qurl.link gate on this via skipIfResolveEndpointDisabled so
	// they keep running where the surface is live (prod, and the localhost
	// stack) and skip cleanly where the JS-agent replaced it (sandbox).
	//
	// local is true: the self-contained stack serves /health and the
	// /plugins dispatcher on localhost:8888, and the JS-agent teardown is a
	// deployed-env concern. The invariant
	// `ResolveEndpointEnabled == !qurlLinkJSAgentEnabledEnvs[env]` holds for
	// every env and is fenced against drift in dns_test.go.
	ResolveEndpointEnabled bool

	// RelayBaseURL is the public HTTPS ingress for the NHP-Relay
	// (relay.qurl.link.layerv.xyz in sandbox), the browser-knock front door
	// that replaces the resolve NLB under the JS-agent topology. Empty in
	// envs without a deployed relay (local, and prod until deploy_relay
	// flips). The relay ALB terminates TLS and forwards only POST/OPTIONS
	// /relay/*; every other path (including /health/live, which is the
	// ALB-internal target health-check path) returns a 404 default action,
	// so the only externally-assertable relay surface is its TLS
	// certificate — TestProtocol_NLBTLSCertValid re-homes here when the
	// resolve endpoint is disabled. Mirrors the env's relay_dns_name tfvar.
	RelayBaseURL string
}

// deriveEndpoints returns the default URL set for the named environment.
// Adding a new environment (e.g., staging) means adding a case here —
// no test body needs to change.
//
// FOUR-PLACE UPDATE: this is one of four sites that must be updated
// in lockstep when adding a new env that participates in the qurl-
// service internal-ALB rollout (PRs #1588/#1596/#1608/#1628/#1635):
//
//  1. This function (the in-test hostname mapping).
//  2. `.github/workflows/nhp-smoke-tests.yml`'s `||` chain on
//     `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED` (workflow-level
//     gate; without it, the 07_/08_/09_ tests silently skip).
//  3. The env's tfvars: `qurl_internal_service_domain`.
//  4. `tests/smoke/09_public_alb_internal_lockdown_test.go`'s
//     `httpListenerOptOutEnvs` map (an env that disables the
//     public HTTP listener opts out of the HTTP-redirect fence).
//     Empty today — both sandbox and prod publish port 80.
//
// nhp#1640 tracks moving all four to SSM-sourced so the workflow,
// this function, and the test-side map stop being a duplicate-of-
// truth.
func deriveEndpoints(env string) (derivedEndpoints, error) {
	switch env {
	case "local":
		// Self-contained local stack (scripts/run-smoke.sh brings up
		// nhp-server + dynamodb-local via docker compose). Only the NHP
		// server's HTTP plugin/health endpoint exists locally — there is
		// no CloudFront origin, no qurl-service, and no Auth0, so the
		// qURL-minting and internal-ALB fences are excluded from the
		// curated `local` tier (and skip via requireRemote if invoked
		// directly). The four-place internal-ALB lockstep noted above
		// does NOT apply to local: QURLInternalAPIHostname is empty.
		// Override the base URL with NHP_SERVER_BASE_URL when the compose
		// stack maps the HTTP port somewhere other than the default.
		return derivedEndpoints{
			NHPServerBaseURL:        "http://localhost:8888",
			NHPServerOriginURL:      "",
			QURLAPIBaseURL:          "",
			QURLInternalAPIHostname: "",
			QURLSiteDomain:          "qurl.site.local", // apex-format guard (#1329) only; unused on local (no qURL path runs)
			QURLLinkOrigin:          "http://localhost:8888",
			ResolveEndpointEnabled:  true, // localhost:8888 serves /health + /plugins for the curated local tier
			RelayBaseURL:            "",   // no relay in the self-contained stack
		}, nil
	case "sandbox":
		return derivedEndpoints{
			NHPServerBaseURL:        "https://resolve.qurl.link.layerv.xyz",
			NHPServerOriginURL:      "https://resolve-origin.qurl.link.layerv.xyz",
			QURLAPIBaseURL:          "https://api.layerv.xyz",
			QURLInternalAPIHostname: "internal-api.qurl.layerv.xyz",
			QURLSiteDomain:          "qurl.site.layerv.xyz",
			QURLLinkOrigin:          "https://qurl.link.layerv.xyz",
			// sandbox runs the browser JS-agent + relay topology
			// (qurl_link_js_agent_enabled = true), so the legacy server-side
			// resolve.qurl.link surface is torn down; the relay is the live
			// HTTPS ingress (deploy_relay = true, relay_dns_name below).
			ResolveEndpointEnabled: false,
			RelayBaseURL:           "https://relay.qurl.link.layerv.xyz",
		}, nil
	case "prod":
		return derivedEndpoints{
			NHPServerBaseURL:        "https://resolve.qurl.link",
			NHPServerOriginURL:      "https://resolve-origin.qurl.link",
			QURLAPIBaseURL:          "https://api.layerv.ai",
			QURLInternalAPIHostname: "internal-api.qurl.layerv.ai",
			// Prod uses the registered apex `qurl.site` directly, so
			// per-resource hosts are r_{id}.qurl.site (not the
			// sandbox-style `qurl.site.layerv.xyz`). Mirrors the
			// terraform/environments/prod qurl_site_domain value.
			QURLSiteDomain: "qurl.site",
			QURLLinkOrigin: "https://qurl.link",
			// prod still serves the legacy resolve endpoint
			// (qurl_link_js_agent_enabled = false). The relay is not yet
			// deployed in prod (deploy_relay = false), so RelayBaseURL stays
			// empty until prod adopts the JS-agent topology.
			ResolveEndpointEnabled: true,
			RelayBaseURL:           "",
		}, nil
	default:
		return derivedEndpoints{}, fmt.Errorf("unknown environment %q (want local, sandbox, or prod)", env)
	}
}
