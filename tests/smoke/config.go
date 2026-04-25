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

// requireActiveColor reads /{env}/nhp/server/active-color from SSM
// and fails the test (not skip) if it is missing or not one of
// {blue, green}.
//
// Fail-loud policy: a missing SSM parameter here means either the
// deploy pipeline hasn't written it yet (broken deploy) or the
// smoke IAM role can't read it (broken role). Either way, silently
// skipping the whole Tier 1 suite is the wrong signal — we want
// CI to turn red.
func requireActiveColor(t *testing.T) string {
	t.Helper()
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
// Fails loudly if ActiveColor is not {blue, green}.
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

// requireActiveServerASG returns the active-color server ASG name
// from SSM at /{env}/nhp/server/{active}-asg-name. Fails loudly if
// missing.
func requireActiveServerASG(t *testing.T) string {
	t.Helper()
	return requireColoredASG(t, "server", requireActiveColor(t))
}

// requireActiveACASG returns the active-color AC ASG name from SSM
// at /{env}/nhp/ac/{active}-asg-name. Fails loudly if missing.
func requireActiveACASG(t *testing.T) string {
	t.Helper()
	return requireColoredASG(t, "ac", requireActiveColor(t))
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
