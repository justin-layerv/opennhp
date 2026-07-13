//go:build smoke

package smoke

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Deploy-mode constants. Wire-level values matching what
// terraform/main.tf::aws_ssm_parameter.deploy_mode writes to
// /{env}/nhp/deploy/mode. Use these constants in switch statements
// and skip helpers; bare literals only at the wire-contract
// validation site in fetchDeployDiscovery.
const (
	DeployModeBlueGreen = "blue_green"
	DeployModeCanary    = "canary"
)

// TestConfig holds configuration shared across smoke tests. Populated
// once in TestMain (setup_test.go) and then read — never mutated — by
// every test.
//
// This struct lives in a non-test file so that other non-test helpers
// (ssm_probe.go) can take a *TestConfig or read testConfig without
// running into the "can't use _test.go identifiers from regular .go"
// compile rule.
type TestConfig struct {
	Environment string // "local", "sandbox", or "prod"

	// DeployMode is the deployment model in effect for this
	// environment: DeployModeBlueGreen or DeployModeCanary. Sourced
	// from the SSM parameter /{env}/nhp/deploy/mode (Terraform-owned,
	// see terraform/main.tf::aws_ssm_parameter.deploy_mode). Used by
	// skipIfNotBlueGreen / skipIfNotCanary to gate mode-specific
	// tests, and by the require*ASG helpers to pick the right
	// SSM-backed ASG name (active-color in blue/green vs the single
	// asg-name in canary).
	DeployMode string

	// CellID is the active cell identifier for this environment.
	// Sourced from /{env}/nhp/deploy/cell-id (Terraform-owned, see
	// terraform/main.tf::aws_ssm_parameter.cell_id). Today every env
	// is single-cell with cell_id = "cell0"; #1448 tracks multi-cell
	// discovery.
	CellID string

	// NHPServerBaseURL is the NHP server's publicly-reachable NLB
	// endpoint (resolve.qurl.link.layerv.xyz in sandbox,
	// resolve.qurl.link in prod). TLS-terminated at the NLB HTTPS
	// listener on 443 and forwarded to nhp-server's port 8888.
	// This is where /health/* and /plugins/* live. It is NOT the
	// QURL API.
	//
	// Tier 2 resolve tests also hit /plugins/qurl on this same host,
	// so there's no separate ResolveBaseURL field.
	NHPServerBaseURL string

	// NHPServerOriginURL is the NLB-direct URL for the NHP server's
	// HTTPS plugin endpoint, used by tests that need to bypass CloudFront
	// (specifically the keep-alive idle-timeout fence in
	// 09_resolve_origin_idle_timeout_test.go — CF's origin connection
	// pool would mask server-side timeout behavior). Empty in environments
	// without a separate origin record. Sourced from
	// `derivedEndpoints.NHPServerOriginURL`.
	NHPServerOriginURL string

	// QURLAPIBaseURL is the QURL service API host (api.layerv.xyz in
	// sandbox, api.layerv.ai in prod). Distinct from NHPServerBaseURL —
	// this is what the NHP /plugins/qurl handler calls outbound to POST
	// /internal/v1/resolve. The remaining smoke consumer is the
	// public-ALB /internal/* lockdown fence (09_public_alb_internal_lockdown),
	// which targets this host. (qURL-minting resolve tests were moved out
	// of nhp — see tests/smoke/CLAUDE.md.)
	QURLAPIBaseURL string

	// QURLInternalAPIHostname is the bare hostname for the qurl-service
	// internal ALB (internal-api.qurl.layerv.{xyz,ai}). Resolves to
	// RFC1918 addresses via the workload-account private hosted zone
	// from inside the VPC and to NXDOMAIN from the public internet.
	// Used by qurl-service #335 rollout fence tests in
	// 07_qurl_internal_alb_test.go. Stored as a hostname (not URL) so
	// tests can both `dig` it directly and concat into URLs.
	QURLInternalAPIHostname string

	// QURLInternalALBEnabled gates the 07_qurl_internal_alb_test.go
	// fences. The hostname is pinned in dns.go regardless (so
	// dns_test.go can fence the per-env value), but the live-system
	// assertions only run once the deploy job confirms the ALB is up.
	// During the rollout window between PR1 merge and the sandbox 1A
	// apply — and during any future rollback to a state without the
	// internal ALB — this stays false and the fences skip cleanly.
	// Sourced from NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED env var.
	QURLInternalALBEnabled bool

	// QURLSiteDomain is the parent domain of per-resource qurl.site
	// hostnames. Retained for the deriveEndpoints regression fence
	// (dns_test.go, the #1329 registered-apex guard); the qURL resolve
	// tests that asserted cookie Domain / 302 Location against it were
	// moved out of nhp (see tests/smoke/CLAUDE.md).
	QURLSiteDomain string

	// QURLLinkOrigin is the origin (scheme + host) of the qurl.link
	// page that the SPA loads from. Tier 2 negotiation tests use it
	// as the Origin header on cross-origin fetch() simulations and
	// assert the server echoes it back in Access-Control-Allow-Origin.
	QURLLinkOrigin string

	// ResolveEndpointEnabled reports whether the nhp-server's HTTP surface
	// (/health/*, /plugins/*, and the qURL token-resolution path) is served
	// at NHPServerBaseURL in this env. False in envs that run the browser
	// JS-agent + relay topology (qurl_link_js_agent_enabled = true), which
	// tears down the legacy resolve.qurl.link NLB/HTTPS surface. Gated tests
	// use skipIfResolveEndpointDisabled. See derivedEndpoints.ResolveEndpointEnabled.
	ResolveEndpointEnabled bool

	// RelayBaseURL is the public HTTPS NHP-Relay ingress for this env
	// (relay.qurl.link.layerv.xyz in sandbox), or empty where no relay is
	// deployed. The protocol-surface TLS test re-homes here when the resolve
	// endpoint is disabled. See derivedEndpoints.RelayBaseURL.
	RelayBaseURL string

	// AllowSSMProbes gates every SSM RunShellScript call. Sandbox runs
	// with true; prod defaults to false during the 30-day burn-in.
	AllowSSMProbes bool

	// Blue/green context (ASG names, active color, TG/listener ARNs)
	// is read directly from SSM at /{env}/nhp/{server,ac}/* via the
	// helpers in aws_helpers.go. No env vars needed — the CI workflow
	// doesn't need to pre-resolve these, and local runs work the
	// same way as CI.

	AWSRegion string

	HTTPClient       *http.Client
	NoRedirectClient *http.Client

	SSMClient    *ssm.Client
	EC2Client    *ec2.Client
	ASGClient    *autoscaling.Client
	CWClient     *cloudwatch.Client
	CWLogsClient *cloudwatchlogs.Client
	DDBClient    *dynamodb.Client
	ELBClient    *elasticloadbalancingv2.Client
	SNSClient    *sns.Client
}

// testConfig is the package-global config populated in TestMain.
// Tests read it directly; non-test helpers (ssm_probe.go) take a
// *TestConfig parameter so they're callable from unit tests without
// the package-global being set.
var testConfig *TestConfig

// getEnvOrDefault returns the value of key, or def if key is unset or
// empty.
func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvLocal is the NHP_ENVIRONMENT value for the self-contained local stack
// (nhp-server + AC + dynamodb-local) brought up by scripts/run-smoke.sh,
// as opposed to a deployed sandbox/prod environment. Local runs have no AWS
// control-plane (SSM/CloudWatch/ASG/...) and no Auth0/qurl-service, so the
// AWS-infra and qURL fences skip via requireRemote and the curated `local`
// tier in scripts/run-smoke.sh selects only the wire-contract subset.
const EnvLocal = "local"

// IsLocal reports whether the suite is running against the local stack.
func (c *TestConfig) IsLocal() bool { return c.Environment == EnvLocal }

// requireRemote skips the test cleanly when running against the local stack.
// Use at the top of any test (or shared helper) that asserts AWS-deployed
// infrastructure — SSM params, ASG/blue-green/canary state, CloudWatch
// alarms/logs, EIP pools, the instance Docker image — or that mints qURLs
// via Auth0 + qurl-service. None of that exists in the local target.
//
// The curated `local` tier in scripts/run-smoke.sh is the primary selector
// (it runs only the wire-contract subset); this is defense in depth so a
// remote-only test invoked under NHP_ENVIRONMENT=local skips cleanly instead
// of dereferencing a nil AWS client. It mirrors the skipIfNot* naming: a
// local target is a deliberate POLICY state, not a broken-setup state.
func requireRemote(t *testing.T) {
	t.Helper()
	if testConfig.IsLocal() {
		t.Skip("skipped: NHP_ENVIRONMENT=local (self-contained stack) — this fence needs a deployed AWS environment")
	}
}

// requireCWLogs fails the test if the CloudWatch Logs client is not
// initialized. Setup unconditionally sets this, so nil indicates a
// broken harness — fail hard, not skip (like the other require* helpers).
func requireCWLogs(t *testing.T) {
	t.Helper()
	requireRemote(t)
	if testConfig.CWLogsClient == nil {
		t.Fatal("CWLogsClient not initialized — setup did not run or AWS config failed")
	}
}

// skipIfNoSSMProbes is named "skip..." (not "require...") because
// SSM probes being disabled is a deliberate POLICY state — prod
// runs with AllowSSMProbes=false during the 30-day burn-in — not a
// broken-setup state. Compare the require* helpers (e.g. requireCWLogs),
// which t.Fatal on missing setup because that IS a broken-setup state. The
// require/skipIf name prefixes make the intended severity legible
// at the call site.
func skipIfNoSSMProbes(t *testing.T) {
	t.Helper()
	if !testConfig.AllowSSMProbes {
		t.Skip("NHP_SMOKE_ALLOW_SSM_PROBES not set to true — SSM probes disabled in this environment")
	}
}

// skipIfQurlInternalALBDisabled skips the test cleanly when the
// qurl-service internal ALB is not yet live in this env (rollout in
// progress between PR1 stage-1A apply and PR2/PR3 consumer flips, or
// during a rollback). Like skipIfNoSSMProbes, this is a POLICY state
// — both PR1 and PR2 must apply before the gate flips on — not a
// broken-setup state.
func skipIfQurlInternalALBDisabled(t *testing.T) {
	t.Helper()
	if !testConfig.QURLInternalALBEnabled {
		t.Skip("NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED not set — internal ALB not yet live in this env (rollout in progress, or rolled back)")
	}
}

// skipIfResolveEndpointDisabled skips the test cleanly when this env does
// not serve the nhp-server HTTP surface at NHPServerBaseURL — i.e. when the
// browser JS-agent + relay topology (qurl_link_js_agent_enabled = true) has
// torn down the legacy resolve.qurl.link NLB/HTTPS surface that hosts
// /health/*, /plugins/*, the qURL token-resolution path, and the server's
// blue/green HTTPS listener. Like skipIfNoSSMProbes / skipIfQurlInternalALBDisabled,
// the disabled state is a deliberate deployment TOPOLOGY, not a broken setup,
// so this skips rather than fails. Tests that fence that surface keep running
// where it is live (prod, and the localhost stack) and skip in JS-agent envs
// (sandbox today). The TLS-cert fence re-homes to the relay instead — see
// nhpIngressTLSURL.
func skipIfResolveEndpointDisabled(t *testing.T) {
	t.Helper()
	if !testConfig.ResolveEndpointEnabled {
		t.Skipf("skipped: env %q runs the JS-agent + relay topology — the legacy server-side resolve.qurl.link surface (/health, /plugins, resolve) is not deployed", testConfig.Environment)
	}
}

// nhpIngressTLSURL returns the env's externally-reachable NHP HTTPS ingress
// for TLS-surface assertions: the resolve endpoint (NHPServerBaseURL) where it
// is live, else the NHP-Relay (RelayBaseURL) under the JS-agent topology. The
// second return is false when neither is reachable from the runner, so the
// caller can skip. Only the relay ALB's TLS termination is externally
// assertable in JS-agent envs; its routes 404 by default (see
// derivedEndpoints.RelayBaseURL).
//
// The resolve-on branch returns ("", false) for the localhost stack (plain
// HTTP, no TLS). That path is unreachable on the deployed path — the only
// runtime caller, TestProtocol_NLBTLSCertValid, gates on requireRemote(t)
// first — so the https:// guard is defense-in-depth that keeps the helper
// correct in isolation, not live local logic (config_test.go locks all four
// branches directly).
func (c *TestConfig) nhpIngressTLSURL() (string, bool) {
	if c.ResolveEndpointEnabled {
		if strings.HasPrefix(c.NHPServerBaseURL, "https://") {
			return c.NHPServerBaseURL, true
		}
		return "", false // localhost stack is plain HTTP — no TLS surface
	}
	if c.RelayBaseURL != "" {
		return c.RelayBaseURL, true
	}
	return "", false
}

// skipIfNotBlueGreen skips the test cleanly when DeployMode is not
// blue/green. Use at the top of tests that fence blue/green-specific
// invariants (active/inactive ASGs, color-coded TGs, listener
// default-action flips). The canary equivalents — when one exists —
// live in a sibling _canary_ test file and gate on skipIfNotCanary.
func skipIfNotBlueGreen(t *testing.T) {
	t.Helper()
	if testConfig.DeployMode != DeployModeBlueGreen {
		t.Skipf("skipped: env %q uses %s deploys, not blue/green", testConfig.Environment, testConfig.DeployMode)
	}
}

// skipIfNotCanary is the symmetric counterpart to skipIfNotBlueGreen.
// Use at the top of canary-specific tests (state-machine state, single
// ASG-only invariants).
func skipIfNotCanary(t *testing.T) {
	t.Helper()
	if testConfig.DeployMode != DeployModeCanary {
		t.Skipf("skipped: env %q uses %s deploys, not canary", testConfig.Environment, testConfig.DeployMode)
	}
}

// requireActiveColor reads the NHP server's active blue/green color from
// /{env}/nhp/server/active-color. See requireActiveColorForComponent for the
// fail-loud and mode-gate policy.
func requireActiveColor(t *testing.T) string {
	t.Helper()
	return requireActiveColorForComponent(t, "server")
}

// requireActiveACColor reads the AC's active blue/green color from
// /{env}/nhp/ac/active-color. The AC and the server flip INDEPENDENTLY — each
// has its own active-color SSM param and its own blue/green ASG + TG set, and a
// per-component deploy can leave them on different colors (e.g. server=blue
// while the AC has rolled to green). AC-side assertions must therefore resolve
// the AC's own color, not reuse the server's; see
// TestBlueGreen_ActiveListenersPointToActiveColorTGs.
func requireActiveACColor(t *testing.T) string {
	t.Helper()
	return requireActiveColorForComponent(t, "ac")
}

// requireActiveColorForComponent reads /{env}/nhp/{component}/active-color from
// SSM and fails the test (not skip) if it is missing or not one of
// {blue, green}.
//
// Fail-loud policy: a missing SSM parameter here means either the
// deploy pipeline hasn't written it yet (broken deploy) or the
// smoke IAM role can't read it (broken role). Either way, silently
// skipping the whole Tier 1 suite is the wrong signal — we want
// CI to turn red.
//
// Defensive mode check: callers in canary envs are supposed to gate
// with skipIfNotBlueGreen first. A forgotten gate would otherwise
// surface as a confusing "active-color SSM is missing" error in
// canary mode; the explicit fatal points the operator at the
// missing gate instead.
func requireActiveColorForComponent(t *testing.T, component string) string {
	t.Helper()
	requireRemote(t)
	if testConfig.DeployMode != DeployModeBlueGreen {
		t.Fatalf("requireActiveColorForComponent[%s] called in deploy mode %q — gate the caller with skipIfNotBlueGreen(t) first",
			component, testConfig.DeployMode)
	}
	name := "/" + testConfig.Environment + "/nhp/" + component + "/active-color"
	val, ok := getSSMParameter(t, name)
	if !ok {
		t.Fatalf("SSM parameter %s is missing — cannot determine active color", name)
	}
	if val != "blue" && val != "green" {
		t.Fatalf("SSM parameter %s = %q, want 'blue' or 'green'", name, val)
	}
	return val
}

// inactiveColorForComponent returns the standby color for a component — the
// opposite of its OWN active color. Server and AC flip independently, so a
// caller touching an AC resource must pass "ac" (not reuse the server's
// inactive color, which can differ when the colors diverge). Fails loudly if
// the active color is not {blue, green}. Blue/green only.
func inactiveColorForComponent(t *testing.T, component string) string {
	t.Helper()
	// requireActiveColorForComponent already validates the SSM value is exactly
	// {blue, green} (it fatals otherwise), so the standby color is just the other
	// one — no second validation/default arm needed here.
	if requireActiveColorForComponent(t, component) == "blue" {
		return "green"
	}
	return "blue"
}

// requireActiveServerASG returns the ASG name for the currently-serving
// server ASG. In blue/green mode it resolves to the active-color ASG via
// /{env}/nhp/server/{active}-asg-name. In canary mode there is only one
// ASG and it lives at /{env}/nhp/server/asg-name. Fails loudly if the
// expected SSM key is missing.
func requireActiveServerASG(t *testing.T) string {
	t.Helper()
	return requireServingASG(t, "server")
}

// requireActiveACASG returns the ASG name for the currently-serving
// AC ASG. Same blue_green-vs-canary resolution as requireActiveServerASG.
func requireActiveACASG(t *testing.T) string {
	t.Helper()
	return requireServingASG(t, "ac")
}

// requireServingASG dispatches to the right SSM lookup for the
// component based on testConfig.DeployMode. It exists so the rest of
// the suite stays mode-agnostic — every test that wants "the ASG
// currently taking traffic" calls require*ASG without caring whether
// the env is blue/green or canary.
func requireServingASG(t *testing.T, component string) string {
	t.Helper()
	requireRemote(t)
	switch testConfig.DeployMode {
	case DeployModeBlueGreen:
		// Resolve the COMPONENT's own active color — the server and AC flip
		// independently (observed sandbox: server=blue, AC=green), so using the
		// server color for an AC ASG would return the AC's standby ASG and make
		// 02_ac_ebpf_objects / 05_ac_eip_pool assert against the wrong fleet.
		return requireColoredASG(t, component, requireActiveColorForComponent(t, component))
	case DeployModeCanary:
		// /{env}/nhp/{component}/asg-name is created in BOTH modes
		// (terraform/modules/compute/main.tf::aws_ssm_parameter.asg_name
		// and modules/ac/main.tf::aws_ssm_parameter.asg_name), but
		// in blue/green it points at one specific color ASG and
		// doesn't follow active-color flips — that's why the
		// blue/green branch above goes through requireColoredASG.
		//
		// TODO(#1448): this lookup is env-scoped, but the canary
		// state tests use cell-scoped keys (/{env}/nhp/{cell_id}/...).
		// Multi-cell rollout needs both shapes migrated together.
		name := "/" + testConfig.Environment + "/nhp/" + component + "/asg-name"
		val, ok := getSSMParameter(t, name)
		if !ok {
			t.Fatalf("SSM parameter %s is missing — cannot locate %s ASG in canary env", name, component)
		}
		return val
	default:
		// Unreachable under normal test invariants — TestMain's
		// fetchDeployDiscovery validates the same enum and exits
		// the process before any test runs. This branch only fires
		// if a test explicitly mutates testConfig.DeployMode mid-run,
		// which the suite doesn't do.
		t.Fatalf("unexpected DeployMode %q (want %s or %s)", testConfig.DeployMode, DeployModeBlueGreen, DeployModeCanary)
		return ""
	}
}

// requireColoredASG reads /{env}/nhp/{component}/{color}-asg-name
// from SSM. component is "server" or "ac"; color is "blue" or
// "green". Failing (not skipping) on missing — see requireActiveColor.
func requireColoredASG(t *testing.T, component, color string) string {
	t.Helper()
	name := "/" + testConfig.Environment + "/nhp/" + component + "/" + color + "-asg-name"
	val, ok := getSSMParameter(t, name)
	if !ok {
		t.Fatalf("SSM parameter %s is missing — cannot locate %s/%s ASG", name, component, color)
	}
	return val
}
