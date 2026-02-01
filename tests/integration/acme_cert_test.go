//go:build integration

// Package integration provides integration tests for ACME certificate management.
//
// These tests verify the Lambda function and related infrastructure are
// deployed correctly. Run after terraform apply.
//
// Run with: go test -v ./tests/integration/... -tags=integration -run TestACME
//
// Required environment variables:
// - AWS_REGION: AWS region where infrastructure is deployed
// - ACME_LAMBDA_NAME: Name of the ACME certificate manager Lambda (optional)
// - ACME_SECRET_ARN: ARN of the certificate secret (optional)
package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// TestACMECertLambdaExists verifies the Lambda function is deployed.
func TestACMECertLambdaExists(t *testing.T) {
	ctx := context.Background()

	lambdaName := os.Getenv("ACME_LAMBDA_NAME")
	if lambdaName == "" {
		lambdaName = "layerv-nhp-sandbox-acme-cert-manager"
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := lambda.NewFromConfig(cfg)

	result, err := client.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: &lambdaName,
	})
	if err != nil {
		t.Fatalf("Lambda function not found: %v", err)
	}

	// Verify configuration
	fnConfig := result.Configuration
	if fnConfig == nil {
		t.Fatal("Lambda configuration is nil")
	}

	// Check runtime
	if fnConfig.Runtime != types.RuntimePython312 {
		t.Errorf("Expected runtime %s, got %s", types.RuntimePython312, fnConfig.Runtime)
	}

	// Check architecture
	if len(fnConfig.Architectures) == 0 || fnConfig.Architectures[0] != types.ArchitectureX8664 {
		t.Errorf("Expected architecture %s, got %v", types.ArchitectureX8664, fnConfig.Architectures)
	}

	// Check handler
	if fnConfig.Handler == nil || *fnConfig.Handler != "acme_cert_manager.handler" {
		t.Errorf("Expected handler acme_cert_manager.handler, got %v", fnConfig.Handler)
	}

	// Check timeout is reasonable (ACME operations can take time)
	if fnConfig.Timeout == nil || *fnConfig.Timeout < 60 {
		t.Errorf("Expected timeout >= 60s, got %v", fnConfig.Timeout)
	}

	t.Logf("Lambda function verified: %s", *fnConfig.FunctionName)
	t.Logf("  Runtime: %s", fnConfig.Runtime)
	t.Logf("  Memory: %d MB", *fnConfig.MemorySize)
	t.Logf("  Timeout: %d s", *fnConfig.Timeout)
}

// TestACMECertLambdaCheckStatus invokes the Lambda to check certificate status.
func TestACMECertLambdaCheckStatus(t *testing.T) {
	ctx := context.Background()

	lambdaName := os.Getenv("ACME_LAMBDA_NAME")
	if lambdaName == "" {
		lambdaName = "layerv-nhp-sandbox-acme-cert-manager"
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := lambda.NewFromConfig(cfg)

	// Invoke with check_status event
	payload := []byte(`{"type": "check_status"}`)

	result, err := client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: &lambdaName,
		Payload:      payload,
	})
	if err != nil {
		t.Fatalf("Failed to invoke Lambda: %v", err)
	}

	// Check for Lambda errors
	if result.FunctionError != nil {
		t.Fatalf("Lambda returned error: %s\nPayload: %s", *result.FunctionError, string(result.Payload))
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(result.Payload, &response); err != nil {
		t.Fatalf("Failed to parse response: %v\nPayload: %s", err, string(result.Payload))
	}

	status, ok := response["status"].(string)
	if !ok {
		t.Fatalf("Response missing status field: %v", response)
	}

	t.Logf("Certificate status: %s", status)

	// Valid statuses: valid, pending, missing, invalid, error
	validStatuses := []string{"valid", "pending", "missing", "invalid", "error"}
	found := false
	for _, vs := range validStatuses {
		if status == vs {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Unexpected status: %s", status)
	}

	// If valid, check additional fields
	if status == "valid" {
		if _, ok := response["days_until_expiry"]; !ok {
			t.Error("Valid certificate missing days_until_expiry")
		}
		if _, ok := response["expires_at"]; !ok {
			t.Error("Valid certificate missing expires_at")
		}
		t.Logf("  Days until expiry: %v", response["days_until_expiry"])
		t.Logf("  Expires at: %v", response["expires_at"])
	}
}

// TestACMECertSecretExists verifies the certificate secret exists.
func TestACMECertSecretExists(t *testing.T) {
	ctx := context.Background()

	secretArn := os.Getenv("ACME_SECRET_ARN")
	if secretArn == "" {
		// Try to find by name pattern
		secretArn = "layerv-nhp-sandbox-tls-certificate"
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	result, err := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: &secretArn,
	})
	if err != nil {
		t.Fatalf("Secret not found: %v", err)
	}

	t.Logf("Certificate secret verified: %s", *result.Name)

	// Check KMS encryption
	if result.KmsKeyId != nil {
		t.Logf("  KMS Key: %s", *result.KmsKeyId)
	} else {
		t.Log("WARNING: Secret not encrypted with customer-managed KMS key")
	}

	// Check rotation
	if result.RotationEnabled != nil && *result.RotationEnabled {
		t.Logf("  Rotation: enabled")
	}
}

// TestACMECertSecretContents verifies the certificate secret has valid structure.
func TestACMECertSecretContents(t *testing.T) {
	ctx := context.Background()

	secretArn := os.Getenv("ACME_SECRET_ARN")
	if secretArn == "" {
		secretArn = "layerv-nhp-sandbox-tls-certificate"
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretArn,
	})
	if err != nil {
		t.Fatalf("Failed to get secret value: %v", err)
	}

	if result.SecretString == nil {
		t.Fatal("Secret has no string value")
	}

	var secret map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		t.Fatalf("Failed to parse secret JSON: %v", err)
	}

	// Check for pending status (not yet generated)
	if status, ok := secret["status"].(string); ok && status == "pending" {
		t.Log("Certificate not yet generated (status: pending)")
		t.Log("Invoke Lambda with force_renew to generate certificate")
		return
	}

	// Check required fields for generated certificate
	requiredFields := []string{"private_key", "certificate", "chain", "fullchain", "domains"}
	for _, field := range requiredFields {
		if _, ok := secret[field]; !ok {
			t.Errorf("Secret missing required field: %s", field)
		}
	}

	// Verify certificate is PEM format
	if cert, ok := secret["certificate"].(string); ok {
		if !strings.Contains(cert, "-----BEGIN CERTIFICATE-----") {
			t.Error("Certificate not in PEM format")
		}
	}

	// Verify private key is PEM format
	if key, ok := secret["private_key"].(string); ok {
		if !strings.Contains(key, "-----BEGIN") {
			t.Error("Private key not in PEM format")
		}
	}

	t.Logf("Certificate secret structure verified")
	if domains, ok := secret["domains"].([]interface{}); ok {
		t.Logf("  Domains: %v", domains)
	}
	if renewedAt, ok := secret["renewed_at"].(string); ok {
		t.Logf("  Renewed at: %s", renewedAt)
	}
}

// TestACMECertBuildPackage verifies the Lambda package was built correctly.
// This is a local test that can run without AWS credentials.
func TestACMECertBuildPackage(t *testing.T) {
	// Check if build directory exists
	buildDir := "terraform/modules/acme-cert/build/package"

	if _, err := os.Stat(buildDir); os.IsNotExist(err) {
		t.Skip("Build directory does not exist - run build.sh first")
	}

	// Check for required files
	requiredFiles := []string{
		"acme_cert_manager.py",
		"acme",
		"josepy",
		"cryptography",
		"dns",
	}

	for _, file := range requiredFiles {
		path := buildDir + "/" + file
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Missing required file/directory: %s", file)
		}
	}

	// Check for Linux-specific binary (cffi)
	cffiPath := buildDir + "/_cffi_backend.cpython-312-x86_64-linux-gnu.so"
	if _, err := os.Stat(cffiPath); os.IsNotExist(err) {
		t.Error("Missing Linux cffi binary - package may not work in Lambda")
	}

	t.Log("Lambda package structure verified")
}
