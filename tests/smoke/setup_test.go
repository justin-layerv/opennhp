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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// TestMain runs once per go test process. It loads configuration from
// environment variables, constructs AWS SDK clients, derives URLs from
// NHP_ENVIRONMENT, and pre-fetches (or reuses) an Auth0 M2M bearer.
//
// The heavy lifting (struct definition, require* helpers, derivation)
// lives in config.go so non-test files can use it too. This file owns
// only the process-level bootstrap.
func TestMain(m *testing.M) {
	ctx := context.Background()

	env := strings.TrimSpace(os.Getenv("NHP_ENVIRONMENT"))
	if env == "" {
		fmt.Fprintln(os.Stderr, "ERROR: NHP_ENVIRONMENT must be set to 'sandbox' or 'prod'")
		os.Exit(2)
	}
	if env != "sandbox" && env != "prod" {
		fmt.Fprintf(os.Stderr, "ERROR: NHP_ENVIRONMENT must be 'sandbox' or 'prod', got %q\n", env)
		os.Exit(2)
	}

	region := getEnvOrDefault("AWS_REGION", "us-east-2")

	derived, err := deriveEndpoints(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: derive endpoints: %v\n", err)
		os.Exit(2)
	}

	testConfig = &TestConfig{
		Environment:       env,
		NHPServerBaseURL:  getEnvOrDefault("NHP_SERVER_BASE_URL", derived.NHPServerBaseURL),
		QURLAPIBaseURL:    getEnvOrDefault("QURL_API_BASE_URL", derived.QURLAPIBaseURL),
		QURLSiteDomain:    getEnvOrDefault("QURL_SITE_DOMAIN", derived.QURLSiteDomain),
		Auth0Domain:       getEnvOrDefault("AUTH0_DOMAIN", "auth.layerv.ai"),
		Auth0Audience:     getEnvOrDefault("AUTH0_AUDIENCE", derived.QURLAPIBaseURL),
		Auth0ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		Auth0ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		AllowSSMProbes:    strings.EqualFold(os.Getenv("NHP_SMOKE_ALLOW_SSM_PROBES"), "true"),
		AWSRegion:         region,
	}

	testConfig.NHPServerBaseURL = strings.TrimSuffix(testConfig.NHPServerBaseURL, "/")
	testConfig.QURLAPIBaseURL = strings.TrimSuffix(testConfig.QURLAPIBaseURL, "/")

	testConfig.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	testConfig.NoRedirectClient = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
	testConfig.ELBClient = elasticloadbalancingv2.NewFromConfig(awsCfg)

	// Pre-fetch (or cache-hit) the Auth0 bearer. Failure is non-fatal
	// for Tier 1 — Auth0-dependent tests will call requireAuth0 and
	// fail explicitly if the token is missing.
	if testConfig.Auth0ClientID != "" && testConfig.Auth0ClientSecret != "" {
		tok, err := getOrMintCachedAuth0Token(ctx, testConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Auth0 token prefetch failed: %v\n", err)
		} else {
			testConfig.CachedAuth0Token = tok
		}
	}

	os.Exit(m.Run())
}
