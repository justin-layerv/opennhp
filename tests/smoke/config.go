//go:build smoke

package smoke

import (
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
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
// (qurl_client.go, ssm_probe.go, auth0.go) can take a *TestConfig or
// read testConfig without running into the "can't use _test.go
// identifiers from regular .go" compile rule.
type TestConfig struct {
	Environment string // "sandbox" or "prod"

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

	// QURLAPIBaseURL is the QURL service API (api.layerv.xyz in
	// sandbox, api.layerv.ai in prod). Distinct from
	// NHPServerBaseURL — this is what the NHP /plugins/qurl handler
	// calls outbound to POST /internal/v1/resolve, and what Tier 2
	// resolve tests call to mint QURLs.
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
	// hostnames. Tier 2 resolve tests assert:
	//   - cookie Domain attribute equals this
	//   - 302 Location host has this as its suffix
	QURLSiteDomain string

	// QURLLinkOrigin is the origin (scheme + host) of the qurl.link
	// page that the SPA loads from. Tier 2 negotiation tests use it
	// as the Origin header on cross-origin fetch() simulations and
	// assert the server echoes it back in Access-Control-Allow-Origin.
	QURLLinkOrigin string

	Auth0Domain       string
	Auth0Audience     string
	Auth0ClientID     string
	Auth0ClientSecret string

	// CachedAuth0Token is the SSM-backed cached bearer populated in
	// TestMain. Empty string means either credentials were unset or
	// the fetch failed; tests gate on this via requireAuth0.
	CachedAuth0Token string

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
	ELBClient    *elasticloadbalancingv2.Client
}

// testConfig is the package-global config populated in TestMain.
// Tests read it directly; non-test helpers (auth0.go, qurl_client.go)
// take a *TestConfig parameter so they're callable from unit tests
// without the package-global being set.
var testConfig *TestConfig

// getEnvOrDefault returns the value of key, or def if key is unset or
// empty.
func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// requireAuth0 fails the test if no Auth0 bearer was pre-fetched.
// Auth0 credentials are mandatory for Tier 2 tests that mint QURLs;
// this helper is a hard fail (not skip) because a missing token is
// usually a CI misconfiguration we want to see, not a silent pass.
func requireAuth0(t *testing.T) string {
	t.Helper()
	if testConfig.CachedAuth0Token == "" {
		t.Fatal("Auth0 token not available — AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET missing or token fetch failed")
	}
	return testConfig.CachedAuth0Token
}

// requireCWLogs fails the test if the CloudWatch Logs client is not
// initialized. Setup unconditionally sets this, so nil indicates a
// broken harness — fail hard, not skip (matches requireAuth0).
func requireCWLogs(t *testing.T) {
	t.Helper()
	if testConfig.CWLogsClient == nil {
		t.Fatal("CWLogsClient not initialized — setup did not run or AWS config failed")
	}
}

// skipIfNoSSMProbes is named "skip..." (not "require...") because
// SSM probes being disabled is a deliberate POLICY state — prod
// runs with AllowSSMProbes=false during the 30-day burn-in — not a
// broken-setup state. Compare requireAuth0, which t.Fatalfs on
// missing credentials because that IS a broken-setup state. The
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

// requireActiveColor reads /{env}/nhp/server/active-color from SSM
// and fails the test (not skip) if it is missing or not one of
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
func requireActiveColor(t *testing.T) string {
	t.Helper()
	if testConfig.DeployMode != DeployModeBlueGreen {
		t.Fatalf("requireActiveColor called in deploy mode %q — gate the caller with skipIfNotBlueGreen(t) first",
			testConfig.DeployMode)
	}
	name := "/" + testConfig.Environment + "/nhp/server/active-color"
	val, ok := getSSMParameter(t, name)
	if !ok {
		t.Fatalf("SSM parameter %s is missing — cannot determine active color", name)
	}
	if val != "blue" && val != "green" {
		t.Fatalf("SSM parameter %s = %q, want 'blue' or 'green'", name, val)
	}
	return val
}

// inactiveColor returns the color opposite to the active color.
// Fails loudly if ActiveColor is not {blue, green}. Blue/green only.
func inactiveColor(t *testing.T) string {
	t.Helper()
	active := requireActiveColor(t)
	switch active {
	case "blue":
		return "green"
	case "green":
		return "blue"
	default:
		t.Fatalf("unexpected active color %q (want blue or green)", active)
		return ""
	}
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
	switch testConfig.DeployMode {
	case DeployModeBlueGreen:
		return requireColoredASG(t, component, requireActiveColor(t))
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
