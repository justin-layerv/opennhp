//go:build smoke

package smoke

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// TestMain runs once per go test process. It loads configuration from
// environment variables, constructs AWS SDK clients, and derives URLs from
// NHP_ENVIRONMENT.
//
// The heavy lifting (struct definition, require* helpers, derivation)
// lives in config.go so non-test files can use it too. This file owns
// only the process-level bootstrap.
func TestMain(m *testing.M) {
	ctx := context.Background()

	env := strings.TrimSpace(os.Getenv("NHP_ENVIRONMENT"))
	if env == "" {
		fmt.Fprintln(os.Stderr, "ERROR: NHP_ENVIRONMENT must be set to 'local', 'sandbox', or 'prod'")
		os.Exit(2)
	}
	if env != EnvLocal && env != "sandbox" && env != "prod" {
		fmt.Fprintf(os.Stderr, "ERROR: NHP_ENVIRONMENT must be 'local', 'sandbox', or 'prod', got %q\n", env)
		os.Exit(2)
	}

	region := getEnvOrDefault("AWS_REGION", "us-east-2")

	derived, err := deriveEndpoints(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: derive endpoints: %v\n", err)
		os.Exit(2)
	}

	testConfig = &TestConfig{
		Environment:             env,
		NHPServerBaseURL:        getEnvOrDefault("NHP_SERVER_BASE_URL", derived.NHPServerBaseURL),
		NHPServerOriginURL:      getEnvOrDefault("NHP_SERVER_ORIGIN_URL", derived.NHPServerOriginURL),
		QURLAPIBaseURL:          getEnvOrDefault("QURL_API_BASE_URL", derived.QURLAPIBaseURL),
		QURLInternalAPIHostname: getEnvOrDefault("QURL_INTERNAL_API_HOSTNAME", derived.QURLInternalAPIHostname),
		QURLSiteDomain:          getEnvOrDefault("QURL_SITE_DOMAIN", derived.QURLSiteDomain),
		QURLLinkOrigin:          getEnvOrDefault("QURL_LINK_ORIGIN", derived.QURLLinkOrigin),
		// ResolveEndpointEnabled intentionally has NO env override: it is a hard
		// topology invariant fenced against qurlLinkJSAgentEnabledEnvs in
		// dns_test.go. RelayBaseURL does take one (a reachable URL worth
		// overriding ad-hoc). Do not add an override for ResolveEndpointEnabled
		// — it would let the drift fence and the runtime value diverge.
		ResolveEndpointEnabled: derived.ResolveEndpointEnabled,
		RelayBaseURL:           getEnvOrDefault("NHP_RELAY_BASE_URL", derived.RelayBaseURL),
		AllowSSMProbes:         strings.EqualFold(os.Getenv("NHP_SMOKE_ALLOW_SSM_PROBES"), "true"),
		QURLInternalALBEnabled: strings.EqualFold(os.Getenv("NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED"), "true"),
		AWSRegion:              region,
	}

	testConfig.NHPServerBaseURL = strings.TrimSuffix(testConfig.NHPServerBaseURL, "/")
	testConfig.NHPServerOriginURL = strings.TrimSuffix(testConfig.NHPServerOriginURL, "/")
	testConfig.QURLAPIBaseURL = strings.TrimSuffix(testConfig.QURLAPIBaseURL, "/")
	testConfig.RelayBaseURL = strings.TrimSuffix(testConfig.RelayBaseURL, "/")

	// Catch the misconfigured combo "ALB enabled but no hostname" before
	// any test runs. Without this, smoke probes interpolate the empty
	// string into `dig ` and `curl https:///...`, producing confusing
	// errors instead of a clear config-mismatch failure.
	if testConfig.QURLInternalALBEnabled && testConfig.QURLInternalAPIHostname == "" {
		fmt.Fprintln(os.Stderr, "ERROR: NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED=true but QURLInternalAPIHostname is empty — set QURL_INTERNAL_API_HOSTNAME or pick an env that defines it in deriveEndpoints")
		os.Exit(2)
	}

	testConfig.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	testConfig.NoRedirectClient = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Local self-contained stack: no AWS control-plane and no Auth0 /
	// qurl-service. scripts/run-smoke.sh brings up nhp-server +
	// dynamodb-local via docker compose; the suite only needs
	// NHPServerBaseURL (default http://localhost:8888, override with
	// NHP_SERVER_BASE_URL when the compose stack maps the port elsewhere).
	// Skip the AWS SDK clients, deploy-mode discovery, and the lockdown-body
	// resolve — the curated `local` tier runs only
	// the wire-contract subset, and any remote-only test reached here skips
	// via requireRemote, skipIfNot{BlueGreen,Canary} (DeployMode stays
	// empty), or skipIfNoSSMProbes (AllowSSMProbes is false).
	if env == EnvLocal {
		fmt.Fprintf(os.Stderr, "smoke: env=local server=%s (self-contained stack; AWS control-plane skipped)\n",
			testConfig.NHPServerBaseURL)
		os.Exit(m.Run())
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: load AWS config: %v\n", err)
		os.Exit(2)
	}
	testConfig.SSMClient = ssm.NewFromConfig(awsCfg)
	testConfig.EC2Client = ec2.NewFromConfig(awsCfg)
	testConfig.ASGClient = autoscaling.NewFromConfig(awsCfg)
	testConfig.CWClient = cloudwatch.NewFromConfig(awsCfg)
	testConfig.CWLogsClient = cloudwatchlogs.NewFromConfig(awsCfg)
	testConfig.DDBClient = dynamodb.NewFromConfig(awsCfg)
	testConfig.ELBClient = elasticloadbalancingv2.NewFromConfig(awsCfg)
	testConfig.SNSClient = sns.NewFromConfig(awsCfg)

	// Resolve deploy mode + cell ID from SSM in one batch. Fail
	// loudly on missing or unknown values — silently defaulting to
	// blue_green would let a misconfigured prod look healthy while
	// running every blue/green-specific assertion against a canary
	// environment that doesn't have the prerequisite SSM keys.
	discovery, err := fetchDeployDiscovery(ctx, testConfig.SSMClient, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: resolve deploy discovery for %s: %v\n", env, err)
		os.Exit(2)
	}
	testConfig.DeployMode = discovery.Mode
	testConfig.CellID = discovery.CellID

	// Log the resolved discovery so CI logs can distinguish
	// "mode/cell resolution wrong" from "test logic wrong" without
	// re-running locally.
	fmt.Fprintf(os.Stderr, "smoke: env=%s mode=%s cell_id=%s region=%s\n",
		env, discovery.Mode, discovery.CellID, region)

	// Resolve the public-ALB /internal/* lockdown expected body from the
	// Terraform-owned SSM parameter, so 09_public_alb_internal_lockdown_test.go
	// asserts the live wire response against an IaC-pinned value rather than a
	// stale Go literal (#1645, Path B — see
	// aws_helpers.go::resolvePublicALBLockdownExpectedBody). Only when the
	// lockdown rule is wired in this env.
	//
	// SCOPED failure (not a suite-wide os.Exit): unlike deploy mode/cell —
	// which every test needs, so fetchDeployDiscovery is fatal — the lockdown
	// body is consumed only by the 09_* fences. A missing/unparseable parameter
	// (terraform out of date, env mis-gated, or the body shape changed without
	// updating the resolver) is recorded here and surfaced as a hard failure of
	// exactly those fences via requirePublicALBLockdownExpectedBody, rather than
	// collateral-aborting unrelated tiers (health, blue/green, resolve, ...).
	if testConfig.QURLInternalALBEnabled {
		body, err := resolvePublicALBLockdownExpectedBody(ctx, env)
		if err != nil {
			publicALBLockdownBodyResolveErr = err
			fmt.Fprintf(os.Stderr, "WARNING: public-ALB lockdown expected body unresolved — 09_* lockdown fences will fail (other tiers unaffected): %v\n", err)
		} else {
			publicALBLockdownExpectedBody = body
			fmt.Fprintf(os.Stderr, "smoke: public-ALB lockdown expected body resolved from SSM: %v\n", body)
		}
	}

	os.Exit(m.Run())
}
