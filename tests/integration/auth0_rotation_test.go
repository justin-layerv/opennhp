// Package integration provides integration tests for Auth0 secret rotation.
// These tests validate the deployed Lambda function, IAM permissions, and
// rotation schedule configuration.
//
// Run with: go test -v ./tests/integration/... -tags=integration -run TestAuth0
//
// Required environment variables:
// - AWS_REGION: AWS region where Auth0 rotation is deployed
// - AUTH0_ROTATION_LAMBDA_ARN: ARN of the rotation Lambda function
// - AUTH0_BACKEND_SECRET_ARN: ARN of the Auth0 backend credentials secret
// - AUTH0_ROTATION_ENABLED: Set to "true" if rotation is enabled
//
//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Auth0 rotation test configuration loaded from environment
type auth0RotationConfig struct {
	region           string
	lambdaARN        string
	secretARN        string
	rotationEnabled  bool
	managementSecret string
}

func loadAuth0RotationConfig(t *testing.T) *auth0RotationConfig {
	t.Helper()

	enabled := os.Getenv("AUTH0_ROTATION_ENABLED")
	if enabled != "true" {
		t.Skip("AUTH0_ROTATION_ENABLED not set to 'true', skipping Auth0 rotation tests")
	}

	lambdaARN := os.Getenv("AUTH0_ROTATION_LAMBDA_ARN")
	if lambdaARN == "" {
		t.Skip("AUTH0_ROTATION_LAMBDA_ARN not set, skipping Auth0 rotation tests")
	}

	return &auth0RotationConfig{
		region:           os.Getenv("AWS_REGION"),
		lambdaARN:        lambdaARN,
		secretARN:        os.Getenv("AUTH0_BACKEND_SECRET_ARN"),
		rotationEnabled:  true,
		managementSecret: os.Getenv("AUTH0_MANAGEMENT_SECRET_ARN"),
	}
}

// TestAuth0Rotation_LambdaExists verifies the rotation Lambda is deployed
func TestAuth0Rotation_LambdaExists(t *testing.T) {
	cfg := loadAuth0RotationConfig(t)

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := lambda.NewFromConfig(awsCfg)

	// Extract function name from ARN
	parts := strings.Split(cfg.lambdaARN, ":")
	functionName := parts[len(parts)-1]

	resp, err := client.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: &functionName,
	})
	if err != nil {
		t.Fatalf("Failed to get Lambda function: %v", err)
	}

	// Verify runtime
	if resp.Configuration.Runtime != "nodejs20.x" {
		t.Errorf("Expected runtime nodejs20.x, got %s", resp.Configuration.Runtime)
	}

	// Verify handler
	if *resp.Configuration.Handler != "rotate_secret.handler" {
		t.Errorf("Expected handler rotate_secret.handler, got %s", *resp.Configuration.Handler)
	}

	// Verify timeout (should be at least 60s for Auth0 API calls)
	if *resp.Configuration.Timeout < 60 {
		t.Errorf("Expected timeout >= 60s, got %d", *resp.Configuration.Timeout)
	}

	// Verify environment variables
	envVars := resp.Configuration.Environment.Variables
	if envVars["AUTH0_DOMAIN"] == "" {
		t.Error("AUTH0_DOMAIN environment variable not set on Lambda")
	}
	if envVars["AUTH0_MANAGEMENT_SECRET_ARN"] == "" {
		t.Error("AUTH0_MANAGEMENT_SECRET_ARN environment variable not set on Lambda")
	}

	t.Logf("Lambda function %s verified: runtime=%s, timeout=%ds",
		functionName, resp.Configuration.Runtime, *resp.Configuration.Timeout)
}

// TestAuth0Rotation_LambdaIAMPermissions verifies the Lambda has required IAM permissions
func TestAuth0Rotation_LambdaIAMPermissions(t *testing.T) {
	cfg := loadAuth0RotationConfig(t)

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	// Get Lambda function to find its role
	lambdaClient := lambda.NewFromConfig(awsCfg)
	parts := strings.Split(cfg.lambdaARN, ":")
	functionName := parts[len(parts)-1]

	funcResp, err := lambdaClient.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: &functionName,
	})
	if err != nil {
		t.Fatalf("Failed to get Lambda function: %v", err)
	}

	roleARN := *funcResp.Configuration.Role
	roleParts := strings.Split(roleARN, "/")
	roleName := roleParts[len(roleParts)-1]

	// Check IAM role policies
	iamClient := iam.NewFromConfig(awsCfg)

	// List attached policies
	policiesResp, err := iamClient.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		t.Fatalf("Failed to list attached policies: %v", err)
	}

	hasBasicExecution := false
	for _, policy := range policiesResp.AttachedPolicies {
		if strings.Contains(*policy.PolicyArn, "AWSLambdaBasicExecutionRole") {
			hasBasicExecution = true
		}
	}

	if !hasBasicExecution {
		t.Error("Lambda role missing AWSLambdaBasicExecutionRole policy")
	}

	// List inline policies
	inlinePoliciesResp, err := iamClient.ListRolePolicies(context.Background(), &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		t.Fatalf("Failed to list inline policies: %v", err)
	}

	hasSecretsPolicy := false
	for _, policyName := range inlinePoliciesResp.PolicyNames {
		if strings.Contains(policyName, "secrets") {
			hasSecretsPolicy = true

			// Get and verify the policy document
			policyResp, err := iamClient.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &policyName,
			})
			if err != nil {
				t.Errorf("Failed to get policy %s: %v", policyName, err)
				continue
			}

			t.Logf("Found secrets policy: %s", policyName)
			t.Logf("Policy document (URL encoded): %s", *policyResp.PolicyDocument)
		}
	}

	if !hasSecretsPolicy {
		t.Error("Lambda role missing secrets access inline policy")
	}

	t.Logf("IAM role %s verified with %d attached policies and %d inline policies",
		roleName, len(policiesResp.AttachedPolicies), len(inlinePoliciesResp.PolicyNames))
}

// TestAuth0Rotation_SecretHasRotationEnabled verifies rotation is configured on the secret
func TestAuth0Rotation_SecretHasRotationEnabled(t *testing.T) {
	cfg := loadAuth0RotationConfig(t)
	if cfg.secretARN == "" {
		t.Skip("AUTH0_BACKEND_SECRET_ARN not set, skipping")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	resp, err := client.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
		SecretId: &cfg.secretARN,
	})
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	if resp.RotationEnabled == nil || !*resp.RotationEnabled {
		t.Error("Rotation is not enabled on the secret")
	}

	if resp.RotationLambdaARN == nil || *resp.RotationLambdaARN != cfg.lambdaARN {
		t.Errorf("Rotation Lambda ARN mismatch: expected %s, got %v",
			cfg.lambdaARN, resp.RotationLambdaARN)
	}

	if resp.RotationRules == nil || resp.RotationRules.AutomaticallyAfterDays == nil {
		t.Error("Rotation rules not configured")
	} else {
		t.Logf("Rotation configured: every %d days", *resp.RotationRules.AutomaticallyAfterDays)
	}

	t.Logf("Secret %s has rotation enabled with Lambda %s",
		*resp.Name, *resp.RotationLambdaARN)
}

// TestAuth0Rotation_SecretStructureValid verifies the secret has the expected structure
func TestAuth0Rotation_SecretStructureValid(t *testing.T) {
	cfg := loadAuth0RotationConfig(t)
	if cfg.secretARN == "" {
		t.Skip("AUTH0_BACKEND_SECRET_ARN not set, skipping")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	resp, err := client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: &cfg.secretARN,
	})
	if err != nil {
		t.Fatalf("Failed to get secret value: %v", err)
	}

	var secret struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Audience     string `json:"audience"`
	}

	if err := json.Unmarshal([]byte(*resp.SecretString), &secret); err != nil {
		t.Fatalf("Failed to parse secret JSON: %v", err)
	}

	if secret.ClientID == "" {
		t.Error("Secret missing client_id")
	}
	if secret.ClientSecret == "" {
		t.Error("Secret missing client_secret")
	}
	if secret.Audience == "" {
		t.Error("Secret missing audience")
	}
	if !strings.HasPrefix(secret.Audience, "https://") {
		t.Errorf("Audience should be an HTTPS URL, got: %s", secret.Audience)
	}

	t.Logf("Secret structure valid: client_id=%s..., audience=%s",
		secret.ClientID[:min(10, len(secret.ClientID))], secret.Audience)
}

// TestAuth0Rotation_ManualTrigger optionally triggers a manual rotation
// This test is skipped by default as it modifies production secrets
func TestAuth0Rotation_ManualTrigger(t *testing.T) {
	if os.Getenv("AUTH0_ROTATION_TRIGGER_TEST") != "true" {
		t.Skip("Set AUTH0_ROTATION_TRIGGER_TEST=true to run manual rotation test")
	}

	cfg := loadAuth0RotationConfig(t)
	if cfg.secretARN == "" {
		t.Skip("AUTH0_BACKEND_SECRET_ARN not set, skipping")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	// Get current version before rotation
	beforeResp, err := client.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
		SecretId: &cfg.secretARN,
	})
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	var currentVersionBefore string
	for versionID, stages := range beforeResp.VersionIdsToStages {
		for _, stage := range stages {
			if stage == "AWSCURRENT" {
				currentVersionBefore = versionID
				break
			}
		}
	}

	t.Logf("Current secret version before rotation: %s", currentVersionBefore)

	// Trigger rotation
	_, err = client.RotateSecret(context.Background(), &secretsmanager.RotateSecretInput{
		SecretId: &cfg.secretARN,
	})
	if err != nil {
		t.Fatalf("Failed to trigger rotation: %v", err)
	}

	t.Log("Rotation triggered, waiting for completion...")

	// Poll for rotation completion (up to 2 minutes)
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Rotation timed out after 2 minutes")
		case <-ticker.C:
			afterResp, err := client.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
				SecretId: &cfg.secretARN,
			})
			if err != nil {
				t.Logf("Failed to describe secret (retrying): %v", err)
				continue
			}

			var currentVersionAfter string
			for versionID, stages := range afterResp.VersionIdsToStages {
				for _, stage := range stages {
					if stage == "AWSCURRENT" {
						currentVersionAfter = versionID
						break
					}
				}
			}

			if currentVersionAfter != currentVersionBefore {
				t.Logf("Rotation completed! New version: %s", currentVersionAfter)
				return
			}

			t.Log("Rotation still in progress...")
		}
	}
}

// TestAuth0Rotation_Summary prints a summary of the Auth0 rotation configuration
func TestAuth0Rotation_Summary(t *testing.T) {
	cfg := loadAuth0RotationConfig(t)

	t.Log("\n=== Auth0 Secret Rotation Summary ===")
	t.Logf("Region:          %s", cfg.region)
	t.Logf("Lambda ARN:      %s", cfg.lambdaARN)
	t.Logf("Secret ARN:      %s", cfg.secretARN)
	t.Logf("Rotation Enabled: %v", cfg.rotationEnabled)
	t.Log("=====================================")
}
