package connectorauthority

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

const (
	testAccountID = "123456789012"
	testRegion    = "us-west-2"
)

func TestConstructorsValidateBoundaryAndTargets(t *testing.T) {
	t.Parallel()

	boundary := Boundary{AccountID: testAccountID, Region: testRegion}
	tests := []struct {
		name    string
		cfg     aws.Config
		bound   Boundary
		targets HubTargets
		field   string
	}{
		{name: "invalid account", cfg: aws.Config{Region: testRegion}, bound: Boundary{AccountID: "123", Region: testRegion}, targets: validHubTargets(), field: "account_id"},
		{name: "empty region", cfg: aws.Config{}, bound: Boundary{AccountID: testAccountID}, targets: validHubTargets(), field: "region"},
		{name: "SDK region mismatch", cfg: aws.Config{Region: "us-east-1"}, bound: boundary, targets: validHubTargets(), field: "sdk_region"},
		{name: "malformed ARN", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "not-an-arn", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "wrong partition", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "arn:aws-us-gov:lambda:us-west-2:123456789012:function:IssueAssignment:active", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "wrong service", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "arn:aws:sqs:us-west-2:123456789012:function:IssueAssignment:active", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "wrong region", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "arn:aws:lambda:us-east-1:123456789012:function:IssueAssignment:active", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "wrong account", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "arn:aws:lambda:us-west-2:999999999999:function:IssueAssignment:active", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "unqualified function", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: "arn:aws:lambda:us-west-2:123456789012:function:IssueAssignment", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "numeric version", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "42"), RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "latest", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "$LATEST"), RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "other named alias", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "live"), RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "case-variant alias", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "Active"), RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "extra qualifier", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "active") + ":extra", RefreshAssignmentAliasARN: aliasARN("RefreshAssignment", "active")}, field: "issue_assignment"},
		{name: "duplicate target", cfg: aws.Config{Region: testRegion}, bound: boundary, targets: HubTargets{IssueAssignmentAliasARN: aliasARN("IssueAssignment", "active"), RefreshAssignmentAliasARN: aliasARN("IssueAssignment", "active")}, field: "refresh_assignment"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewHubClient(test.cfg, test.bound, test.targets)
			var configErr *ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("error = %T %v, want *ConfigError", err, err)
			}
			if configErr.Field != test.field {
				t.Fatalf("field = %q, want %q", configErr.Field, test.field)
			}
		})
	}
}

func TestConstructorsAcceptExactActiveAliasARNs(t *testing.T) {
	t.Parallel()

	cfg := aws.Config{Region: testRegion}
	boundary := Boundary{AccountID: testAccountID, Region: testRegion}
	if _, err := NewHubClient(cfg, boundary, validHubTargets()); err != nil {
		t.Fatalf("NewHubClient: %v", err)
	}
	if _, err := NewCellClient(cfg, boundary, validCellTargets()); err != nil {
		t.Fatalf("NewCellClient: %v", err)
	}
}

func TestConstructorsRequireDistinctRecoveryAliases(t *testing.T) {
	t.Parallel()

	cfg := aws.Config{Region: testRegion}
	boundary := Boundary{AccountID: testAccountID, Region: testRegion}
	hubMissing := validHubTargets()
	hubMissing.IssueCredentialRecoveryAliasARN = ""
	hubDuplicate := validHubTargets()
	hubDuplicate.IssueCredentialRecoveryAliasARN = hubDuplicate.IssueAssignmentAliasARN
	cellMissing := validCellTargets()
	cellMissing.CompleteCredentialRecoveryAliasARN = ""
	cellDuplicate := validCellTargets()
	cellDuplicate.CompleteCredentialRecoveryAliasARN = cellDuplicate.CompleteRegistrationAliasARN

	for _, test := range []struct {
		name  string
		build func() error
		field string
	}{
		{name: "hub missing", build: func() error { _, err := NewHubClient(cfg, boundary, hubMissing); return err }, field: "issue_credential_recovery"},
		{name: "hub duplicate", build: func() error { _, err := NewHubClient(cfg, boundary, hubDuplicate); return err }, field: "issue_credential_recovery"},
		{name: "cell missing", build: func() error { _, err := NewCellClient(cfg, boundary, cellMissing); return err }, field: "complete_credential_recovery"},
		{name: "cell duplicate", build: func() error { _, err := NewCellClient(cfg, boundary, cellDuplicate); return err }, field: "complete_credential_recovery"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var configErr *ConfigError
			if err := test.build(); !errors.As(err, &configErr) || configErr.Field != test.field {
				t.Fatalf("error = %#v, want ConfigError field %q", err, test.field)
			}
		})
	}
}

func TestLambdaClientForcesDefaultEndpointAndOneAttempt(t *testing.T) {
	t.Parallel()

	customEndpoint := "https://attacker.invalid"
	cfg := aws.Config{
		Region:       testRegion,
		BaseEndpoint: &customEndpoint,
		EndpointResolver: aws.EndpointResolverFunc(func(string, string) (aws.Endpoint, error) {
			return aws.Endpoint{URL: customEndpoint}, nil
		}),
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(func(string, string, ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{URL: customEndpoint}, nil
		}),
		RetryMaxAttempts: 9,
		ServiceOptions: []func(string, any){func(service string, options any) {
			if service == lambda.ServiceID {
				options.(*lambda.Options).BaseEndpoint = &customEndpoint
			}
		}},
	}

	options := newLambdaClient(cfg).Options()
	if options.BaseEndpoint != nil || options.EndpointResolver != nil {
		t.Fatalf("endpoint override survived: BaseEndpoint=%v EndpointResolver=%T", options.BaseEndpoint, options.EndpointResolver)
	}
	if options.RetryMaxAttempts != 1 || options.Retryer.MaxAttempts() != 1 {
		t.Fatalf("retry options = max %d, retryer attempts %d", options.RetryMaxAttempts, options.Retryer.MaxAttempts())
	}
}

func validHubTargets() HubTargets {
	return HubTargets{
		IssueAssignmentAliasARN:         aliasARN("IssueAssignment", "active"),
		RefreshAssignmentAliasARN:       aliasARN("RefreshAssignment", "active"),
		IssueCredentialRecoveryAliasARN: aliasARN("IssueCredentialRecovery", "active"),
	}
}

func validCellTargets() CellTargets {
	return CellTargets{
		IssueRegistrationOTPAliasARN:       aliasARN("IssueRegistrationOTP-cell0", "active"),
		ActivateRegistrationAliasARN:       aliasARN("ActivateRegistration-cell0", "active"),
		CompleteRegistrationAliasARN:       aliasARN("CompleteRegistration-cell0", "active"),
		CompleteCredentialRecoveryAliasARN: aliasARN("CompleteCredentialRecovery-cell0", "active"),
	}
}

func aliasARN(functionName, alias string) string {
	return "arn:aws:lambda:" + testRegion + ":" + testAccountID + ":function:" + functionName + ":" + alias
}
