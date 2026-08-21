package connectorauthority

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	testEnvironment = "sandbox"
	testAccountID   = "123456789012"
	testRegion      = "us-west-2"
	testCellID      = "cell0"
)

func TestAuthorityFunctionInventoryIsClosedAndProducesThreePlusFivePerCellNames(t *testing.T) {
	t.Parallel()

	want := map[Operation]authorityFunctionSpec{
		OperationIssueAssignment:            {operationSuffix: "ia"},
		OperationRefreshAssignment:          {operationSuffix: "ra"},
		OperationIssueCredentialRecovery:    {operationSuffix: "icr"},
		OperationIssueRegistrationOTP:       {operationSuffix: "iro", cellScoped: true},
		OperationActivateRegistration:       {operationSuffix: "ar", cellScoped: true},
		OperationCompleteRegistration:       {operationSuffix: "cr", cellScoped: true},
		OperationCompleteCredentialRecovery: {operationSuffix: "ccr", cellScoped: true},
		OperationResolveConnectorResource:   {operationSuffix: "creso", cellScoped: true},
	}
	if len(authorityFunctionInventory) != len(want) {
		t.Fatalf("Authority inventory has %d operations, want %d", len(authorityFunctionInventory), len(want))
	}
	for operation, wantSpec := range want {
		if gotSpec, ok := authorityFunctionInventory[operation]; !ok || gotSpec != wantSpec {
			t.Fatalf("Authority inventory[%q] = %#v, %t; want %#v", operation, gotSpec, ok, wantSpec)
		}
	}

	boundary := validBoundary()
	names := make(map[string]struct{})
	for _, operation := range []Operation{
		OperationIssueAssignment,
		OperationRefreshAssignment,
		OperationIssueCredentialRecovery,
	} {
		name, ok := authorityFunctionName(boundary, "", operation)
		if !ok {
			t.Fatalf("Hub operation %q has no physical name", operation)
		}
		names[name] = struct{}{}
	}
	for _, cellID := range []string{"cell0", "cell1"} {
		for _, operation := range []Operation{
			OperationIssueRegistrationOTP,
			OperationActivateRegistration,
			OperationCompleteRegistration,
			OperationCompleteCredentialRecovery,
			OperationResolveConnectorResource,
		} {
			name, ok := authorityFunctionName(boundary, cellID, operation)
			if !ok {
				t.Fatalf("cell operation %q for %q has no physical name", operation, cellID)
			}
			names[name] = struct{}{}
		}
	}
	if got, wantCount := len(names), 3+5*2; got != wantCount {
		t.Fatalf("physical names = %d, want 3 + 5N = %d", got, wantCount)
	}
	if _, ok := authorityFunctionName(boundary, "", OperationIssueRegistrationOTP); ok {
		t.Fatal("cell operation accepted without a cell identity")
	}
	if _, ok := authorityFunctionName(boundary, testCellID, OperationIssueAssignment); ok {
		t.Fatal("Hub operation accepted a cell identity")
	}
	if _, ok := authorityFunctionName(boundary, "", Operation("unknown")); ok {
		t.Fatal("unknown operation acquired a physical name")
	}
}

func TestConstructorsAcceptExactBlueAndGreenGraphs(t *testing.T) {
	t.Parallel()

	cfg := aws.Config{Region: testRegion}
	for _, environment := range []string{"sandbox", "prod"} {
		for _, color := range []string{"blue", "green"} {
			t.Run(environment+"/"+color, func(t *testing.T) {
				t.Parallel()
				boundary := boundaryForEnvironment(environment)
				cellBoundary := cellBoundaryForEnvironment(environment)
				if _, err := NewHubClient(cfg, boundary, hubTargetsForEnvironment(environment, color)); err != nil {
					t.Fatalf("NewHubClient: %v", err)
				}
				if _, err := NewRegistrationCellClient(
					cfg,
					cellBoundary,
					registrationCellTargetsForEnvironment(environment, color),
				); err != nil {
					t.Fatalf("NewRegistrationCellClient: %v", err)
				}
				if _, err := NewCredentialRecoveryCellClient(
					cfg,
					cellBoundary,
					credentialRecoveryCellTargetForEnvironment(environment, color),
				); err != nil {
					t.Fatalf("NewCredentialRecoveryCellClient: %v", err)
				}
				if _, err := NewConnectorResourceCellClient(
					cfg,
					cellBoundary,
					connectorResourceCellTargetForEnvironment(environment, color),
				); err != nil {
					t.Fatalf("NewConnectorResourceCellClient: %v", err)
				}
			})
		}
	}
}

func TestHubConstructorRejectsBoundaryNameAndAliasDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    aws.Config
		bound  Boundary
		mutate func(*HubTargets)
		field  string
	}{
		{name: "environment", cfg: aws.Config{Region: testRegion}, bound: Boundary{Environment: "staging", AccountID: testAccountID, Region: testRegion}, field: "environment"},
		{name: "account", cfg: aws.Config{Region: testRegion}, bound: Boundary{Environment: testEnvironment, AccountID: "123", Region: testRegion}, field: "account_id"},
		{name: "region", cfg: aws.Config{}, bound: Boundary{Environment: testEnvironment, AccountID: testAccountID}, field: "region"},
		{name: "region host injection", cfg: aws.Config{Region: "attacker.example/path"}, bound: Boundary{Environment: testEnvironment, AccountID: testAccountID, Region: "attacker.example/path"}, field: "region"},
		{name: "SDK region", cfg: aws.Config{Region: "us-east-1"}, bound: validBoundary(), field: "sdk_region"},
		{name: "malformed ARN", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = "not-an-arn" }, field: "issue_assignment"},
		{name: "partition", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) {
			v.IssueAssignmentAliasARN = "arn:aws-us-gov:lambda:us-west-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
		}, field: "issue_assignment"},
		{name: "service", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) {
			v.IssueAssignmentAliasARN = "arn:aws:sqs:us-west-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
		}, field: "issue_assignment"},
		{name: "ARN region", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) {
			v.IssueAssignmentAliasARN = "arn:aws:lambda:us-east-1:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
		}, field: "issue_assignment"},
		{name: "ARN account", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) {
			v.IssueAssignmentAliasARN = "arn:aws:lambda:us-west-2:999999999999:function:layerv-nhp-sandbox-ca-ia:blue"
		}, field: "issue_assignment"},
		{name: "unqualified", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "") }, field: "issue_assignment"},
		{name: "numeric version", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "42") }, field: "issue_assignment"},
		{name: "latest", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "$LATEST") }, field: "issue_assignment"},
		{name: "legacy active", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "active") }, field: "issue_assignment"},
		{name: "other alias", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "live") }, field: "issue_assignment"},
		{name: "case variant", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ia"), "Blue") }, field: "issue_assignment"},
		{name: "extra qualifier", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN += ":extra" }, field: "issue_assignment"},
		{name: "wrong operation", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN(hubFunction("ra"), "blue") }, field: "issue_assignment"},
		{name: "wrong function environment", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueAssignmentAliasARN = aliasARN("layerv-nhp-prod-ca-ia", "blue") }, field: "issue_assignment"},
		{name: "duplicate", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.RefreshAssignmentAliasARN = v.IssueAssignmentAliasARN }, field: "refresh_assignment"},
		{name: "mixed colors", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.RefreshAssignmentAliasARN = aliasARN(hubFunction("ra"), "green") }, field: "refresh_assignment"},
		{name: "missing recovery", cfg: aws.Config{Region: testRegion}, bound: validBoundary(), mutate: func(v *HubTargets) { v.IssueCredentialRecoveryAliasARN = "" }, field: "issue_credential_recovery"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			targets := hubTargets("blue")
			if test.mutate != nil {
				test.mutate(&targets)
			}
			_, err := NewHubClient(test.cfg, test.bound, targets)
			assertConfigError(t, err, test.field)
		})
	}
}

func TestCellTargetsRequireExactFiveOperationsAndOneColor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		bound  CellBoundary
		mutate func(*CellTargets)
		field  string
	}{
		{name: "environment", bound: CellBoundary{Boundary: Boundary{Environment: "staging", AccountID: testAccountID, Region: testRegion}, CellID: testCellID}, field: "environment"},
		{name: "account", bound: CellBoundary{Boundary: Boundary{Environment: testEnvironment, AccountID: "123", Region: testRegion}, CellID: testCellID}, field: "account_id"},
		{name: "region", bound: CellBoundary{Boundary: Boundary{Environment: testEnvironment, AccountID: testAccountID}, CellID: testCellID}, field: "region"},
		{name: "region host injection", bound: CellBoundary{Boundary: Boundary{Environment: testEnvironment, AccountID: testAccountID, Region: "attacker.example/path"}, CellID: testCellID}, field: "region"},
		{name: "empty cell", bound: CellBoundary{Boundary: validBoundary()}, field: "cell_id"},
		{name: "invalid cell", bound: CellBoundary{Boundary: validBoundary(), CellID: "cell--0"}, field: "cell_id"},
		{name: "long cell", bound: CellBoundary{Boundary: validBoundary(), CellID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, field: "cell_id"},
		{name: "wrong cell", bound: validCellBoundary(), mutate: func(v *CellTargets) { v.IssueRegistrationOTPAliasARN = aliasARN(cellFunction("iro", "cell1"), "blue") }, field: "issue_registration_otp"},
		{name: "wrong operation", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.ActivateRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "blue")
		}, field: "activate_registration"},
		{name: "unqualified", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "")
		}, field: "complete_registration"},
		{name: "version", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "7")
		}, field: "complete_registration"},
		{name: "latest", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "$LATEST")
		}, field: "complete_registration"},
		{name: "legacy active", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "active")
		}, field: "complete_registration"},
		{name: "other alias", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "canary")
		}, field: "complete_registration"},
		{name: "mixed colors", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteCredentialRecoveryAliasARN = aliasARN(cellFunction("ccr", testCellID), "green")
		}, field: "complete_credential_recovery"},
		{name: "duplicate", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteCredentialRecoveryAliasARN = v.CompleteRegistrationAliasARN
		}, field: "complete_credential_recovery"},
		{name: "missing recovery", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.CompleteCredentialRecoveryAliasARN = ""
		}, field: "complete_credential_recovery"},
		{name: "missing connector resource", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.ResolveConnectorResourceAliasARN = ""
		}, field: "resolve_connector_resource"},
		{name: "connector resource wrong operation", bound: validCellBoundary(), mutate: func(v *CellTargets) {
			v.ResolveConnectorResourceAliasARN = aliasARN(cellFunction("cr", testCellID), "blue")
		}, field: "resolve_connector_resource"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			targets := cellTargets("blue")
			if test.mutate != nil {
				test.mutate(&targets)
			}
			assertConfigError(t, ValidateCellTargets(test.bound, targets), test.field)
		})
	}
}

func TestBoundaryRegionUsesCanonicalAWSLabelShape(t *testing.T) {
	t.Parallel()

	for _, region := range []string{
		"us-east-1",
		"eu-central-1",
		"ap-southeast-7",
	} {
		t.Run("accept/"+region, func(t *testing.T) {
			t.Parallel()
			if err := validateBoundaryValues(Boundary{
				Environment: testEnvironment,
				AccountID:   testAccountID,
				Region:      region,
			}); err != nil {
				t.Fatalf("validateBoundaryValues(%q): %v", region, err)
			}
		})
	}

	for _, region := range []string{
		"attacker.example",
		"attacker.example/path",
		"https://attacker.example",
		"US-east-1",
		"us_east_1",
		"us-east@evil-1",
		"us--east-1",
		"us-east-west-1",
		"us-east-10",
		" us-east-1",
		"us-east-1 ",
		"aa-bbbbbbbbbbbbbbbbbbbbbbbbbbbb-1",
	} {
		t.Run("reject/"+region, func(t *testing.T) {
			t.Parallel()
			err := validateBoundaryValues(Boundary{
				Environment: testEnvironment,
				AccountID:   testAccountID,
				Region:      region,
			})
			assertConfigError(t, err, "region")
		})
	}
}

func TestRegistrationAndRecoveryClientsKeepNarrowValidatedSubsets(t *testing.T) {
	t.Parallel()

	registrationTests := []struct {
		name   string
		mutate func(*RegistrationCellTargets)
		field  string
	}{
		{name: "missing OTP", mutate: func(v *RegistrationCellTargets) { v.IssueRegistrationOTPAliasARN = "" }, field: "issue_registration_otp"},
		{name: "wrong operation", mutate: func(v *RegistrationCellTargets) {
			v.ActivateRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "blue")
		}, field: "activate_registration"},
		{name: "wrong cell", mutate: func(v *RegistrationCellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", "cell1"), "blue")
		}, field: "complete_registration"},
		{name: "mixed colors", mutate: func(v *RegistrationCellTargets) {
			v.CompleteRegistrationAliasARN = aliasARN(cellFunction("cr", testCellID), "green")
		}, field: "complete_registration"},
	}
	for _, test := range registrationTests {
		t.Run("registration/"+test.name, func(t *testing.T) {
			t.Parallel()
			targets := registrationCellTargets("blue")
			test.mutate(&targets)
			assertConfigError(t, ValidateRegistrationCellTargets(validCellBoundary(), targets), test.field)
		})
	}

	recoveryTests := []struct {
		name  string
		bound CellBoundary
		alias string
		field string
	}{
		{name: "environment", bound: CellBoundary{Boundary: Boundary{Environment: "staging", AccountID: testAccountID, Region: testRegion}, CellID: testCellID}, alias: aliasARN(cellFunction("ccr", testCellID), "blue"), field: "environment"},
		{name: "account", bound: CellBoundary{Boundary: Boundary{Environment: testEnvironment, AccountID: "123", Region: testRegion}, CellID: testCellID}, alias: aliasARN(cellFunction("ccr", testCellID), "blue"), field: "account_id"},
		{name: "region", bound: CellBoundary{Boundary: Boundary{Environment: testEnvironment, AccountID: testAccountID}, CellID: testCellID}, alias: aliasARN(cellFunction("ccr", testCellID), "blue"), field: "region"},
		{name: "cell", bound: CellBoundary{Boundary: validBoundary(), CellID: "Cell0"}, alias: aliasARN(cellFunction("ccr", testCellID), "blue"), field: "cell_id"},
		{name: "empty", bound: validCellBoundary(), field: "complete_credential_recovery"},
		{name: "wrong operation", bound: validCellBoundary(), alias: aliasARN(cellFunction("cr", testCellID), "blue"), field: "complete_credential_recovery"},
		{name: "wrong cell", bound: validCellBoundary(), alias: aliasARN(cellFunction("ccr", "cell1"), "blue"), field: "complete_credential_recovery"},
		{name: "active", bound: validCellBoundary(), alias: aliasARN(cellFunction("ccr", testCellID), "active"), field: "complete_credential_recovery"},
		{name: "version", bound: validCellBoundary(), alias: aliasARN(cellFunction("ccr", testCellID), "7"), field: "complete_credential_recovery"},
		{name: "latest", bound: validCellBoundary(), alias: aliasARN(cellFunction("ccr", testCellID), "$LATEST"), field: "complete_credential_recovery"},
	}
	for _, test := range recoveryTests {
		t.Run("recovery/"+test.name, func(t *testing.T) {
			t.Parallel()
			assertConfigError(t, ValidateCredentialRecoveryCellTarget(test.bound, CredentialRecoveryCellTarget{
				CompleteCredentialRecoveryAliasARN: test.alias,
			}), test.field)
		})
	}

	resourceTests := []struct {
		name  string
		bound CellBoundary
		alias string
		field string
	}{
		{name: "environment", bound: CellBoundary{Boundary: Boundary{Environment: "staging", AccountID: testAccountID, Region: testRegion}, CellID: testCellID}, alias: aliasARN(cellFunction("creso", testCellID), "blue"), field: "environment"},
		{name: "empty", bound: validCellBoundary(), field: "resolve_connector_resource"},
		{name: "wrong operation", bound: validCellBoundary(), alias: aliasARN(cellFunction("cr", testCellID), "blue"), field: "resolve_connector_resource"},
		{name: "wrong cell", bound: validCellBoundary(), alias: aliasARN(cellFunction("creso", "cell1"), "blue"), field: "resolve_connector_resource"},
		{name: "active", bound: validCellBoundary(), alias: aliasARN(cellFunction("creso", testCellID), "active"), field: "resolve_connector_resource"},
	}
	for _, test := range resourceTests {
		t.Run("resource/"+test.name, func(t *testing.T) {
			t.Parallel()
			assertConfigError(t, ValidateConnectorResourceCellTarget(test.bound, ConnectorResourceCellTarget{
				ResolveConnectorResourceAliasARN: test.alias,
			}), test.field)
		})
	}
}

func TestTargetValidatorsDoNotRequireAWSClient(t *testing.T) {
	t.Parallel()

	if err := ValidateHubTargets(validBoundary(), hubTargets("blue")); err != nil {
		t.Fatalf("ValidateHubTargets: %v", err)
	}
	if err := ValidateCellTargets(validCellBoundary(), cellTargets("green")); err != nil {
		t.Fatalf("ValidateCellTargets: %v", err)
	}
	if err := ValidateRegistrationCellTargets(validCellBoundary(), registrationCellTargets("blue")); err != nil {
		t.Fatalf("ValidateRegistrationCellTargets: %v", err)
	}
	if err := ValidateCredentialRecoveryCellTarget(
		validCellBoundary(),
		credentialRecoveryCellTarget("green"),
	); err != nil {
		t.Fatalf("ValidateCredentialRecoveryCellTarget: %v", err)
	}
	if err := ValidateConnectorResourceCellTarget(
		validCellBoundary(),
		connectorResourceCellTarget("green"),
	); err != nil {
		t.Fatalf("ValidateConnectorResourceCellTarget: %v", err)
	}
}

func TestCellConstructorsRejectSDKRegionMismatch(t *testing.T) {
	t.Parallel()

	cfg := aws.Config{Region: "us-east-1"}
	if _, err := NewRegistrationCellClient(cfg, validCellBoundary(), validRegistrationCellTargets()); err == nil {
		t.Fatal("NewRegistrationCellClient accepted wrong SDK region")
	} else {
		assertConfigError(t, err, "sdk_region")
	}
	if _, err := NewCredentialRecoveryCellClient(cfg, validCellBoundary(), validCredentialRecoveryCellTarget()); err == nil {
		t.Fatal("NewCredentialRecoveryCellClient accepted wrong SDK region")
	} else {
		assertConfigError(t, err, "sdk_region")
	}
	if _, err := NewConnectorResourceCellClient(cfg, validCellBoundary(), validConnectorResourceCellTarget()); err == nil {
		t.Fatal("NewConnectorResourceCellClient accepted wrong SDK region")
	} else {
		assertConfigError(t, err, "sdk_region")
	}
}

func TestLambdaClientForcesDefaultEndpointAndOneAttempt(t *testing.T) {
	t.Parallel()

	customEndpoint := "https://attacker.invalid"
	cfg := aws.Config{
		Region:        testRegion,
		BaseEndpoint:  &customEndpoint,
		ClientLogMode: aws.LogRequestWithBody | aws.LogResponseWithBody,
		EndpointResolver: aws.EndpointResolverFunc(func(string, string) (aws.Endpoint, error) {
			return aws.Endpoint{URL: customEndpoint}, nil
		}),
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(func(string, string, ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{URL: customEndpoint}, nil
		}),
		RetryMaxAttempts: 9,
		ConfigSources:    []any{enabledEndpointVariants{}},
		Interceptors: smithyhttp.InterceptorRegistry{
			BeforeExecution: []smithyhttp.BeforeExecutionInterceptor{noopBeforeExecutionInterceptor{}},
		},
		AuthSchemePreference: []string{"attacker"},
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
	if options.EndpointOptions.UseFIPSEndpoint != aws.FIPSEndpointStateDisabled ||
		options.EndpointOptions.UseDualStackEndpoint != aws.DualStackEndpointStateDisabled {
		t.Fatalf(
			"endpoint variants survived: FIPS=%v dual-stack=%v",
			options.EndpointOptions.UseFIPSEndpoint,
			options.EndpointOptions.UseDualStackEndpoint,
		)
	}
	if len(options.Interceptors.BeforeExecution) != 0 {
		t.Fatalf("inherited interceptors survived: %#v", options.Interceptors)
	}
	if len(options.AuthSchemePreference) != 0 {
		t.Fatalf("inherited auth-scheme preference survived: %v", options.AuthSchemePreference)
	}
	if options.RetryMaxAttempts != 1 || options.Retryer.MaxAttempts() != 1 {
		t.Fatalf("retry options = max %d, retryer attempts %d", options.RetryMaxAttempts, options.Retryer.MaxAttempts())
	}
	if options.ClientLogMode != 0 {
		t.Fatalf("Lambda ClientLogMode = %v, want disabled", options.ClientLogMode)
	}
}

type enabledEndpointVariants struct{}

func (enabledEndpointVariants) GetUseFIPSEndpoint(context.Context) (aws.FIPSEndpointState, bool, error) {
	return aws.FIPSEndpointStateEnabled, true, nil
}

func (enabledEndpointVariants) GetUseDualStackEndpoint(context.Context) (aws.DualStackEndpointState, bool, error) {
	return aws.DualStackEndpointStateEnabled, true, nil
}

type noopBeforeExecutionInterceptor struct{}

func (noopBeforeExecutionInterceptor) BeforeExecution(context.Context, *smithyhttp.InterceptorContext) error {
	return nil
}

func validBoundary() Boundary {
	return boundaryForEnvironment(testEnvironment)
}

func boundaryForEnvironment(environment string) Boundary {
	return Boundary{Environment: environment, AccountID: testAccountID, Region: testRegion}
}

func validCellBoundary() CellBoundary {
	return cellBoundaryForEnvironment(testEnvironment)
}

func cellBoundaryForEnvironment(environment string) CellBoundary {
	return CellBoundary{Boundary: boundaryForEnvironment(environment), CellID: testCellID}
}

func validHubTargets() HubTargets {
	return hubTargets("blue")
}

func hubTargets(color string) HubTargets {
	return hubTargetsForEnvironment(testEnvironment, color)
}

func hubTargetsForEnvironment(environment, color string) HubTargets {
	return HubTargets{
		IssueAssignmentAliasARN:         aliasARN(hubFunctionForEnvironment(environment, "ia"), color),
		RefreshAssignmentAliasARN:       aliasARN(hubFunctionForEnvironment(environment, "ra"), color),
		IssueCredentialRecoveryAliasARN: aliasARN(hubFunctionForEnvironment(environment, "icr"), color),
	}
}

func validCellTargets() CellTargets {
	return cellTargets("blue")
}

func cellTargets(color string) CellTargets {
	return cellTargetsForEnvironment(testEnvironment, color)
}

func cellTargetsForEnvironment(environment, color string) CellTargets {
	return CellTargets{
		IssueRegistrationOTPAliasARN:       aliasARN(cellFunctionForEnvironment(environment, "iro", testCellID), color),
		ActivateRegistrationAliasARN:       aliasARN(cellFunctionForEnvironment(environment, "ar", testCellID), color),
		CompleteRegistrationAliasARN:       aliasARN(cellFunctionForEnvironment(environment, "cr", testCellID), color),
		CompleteCredentialRecoveryAliasARN: aliasARN(cellFunctionForEnvironment(environment, "ccr", testCellID), color),
		ResolveConnectorResourceAliasARN:   aliasARN(cellFunctionForEnvironment(environment, "creso", testCellID), color),
	}
}

func validRegistrationCellTargets() RegistrationCellTargets {
	return registrationCellTargets("blue")
}

func registrationCellTargets(color string) RegistrationCellTargets {
	return registrationCellTargetsForEnvironment(testEnvironment, color)
}

func registrationCellTargetsForEnvironment(environment, color string) RegistrationCellTargets {
	return RegistrationCellTargets{
		IssueRegistrationOTPAliasARN: aliasARN(cellFunctionForEnvironment(environment, "iro", testCellID), color),
		ActivateRegistrationAliasARN: aliasARN(cellFunctionForEnvironment(environment, "ar", testCellID), color),
		CompleteRegistrationAliasARN: aliasARN(cellFunctionForEnvironment(environment, "cr", testCellID), color),
	}
}

func validCredentialRecoveryCellTarget() CredentialRecoveryCellTarget {
	return credentialRecoveryCellTarget("blue")
}

func credentialRecoveryCellTarget(color string) CredentialRecoveryCellTarget {
	return credentialRecoveryCellTargetForEnvironment(testEnvironment, color)
}

func credentialRecoveryCellTargetForEnvironment(environment, color string) CredentialRecoveryCellTarget {
	return CredentialRecoveryCellTarget{
		CompleteCredentialRecoveryAliasARN: aliasARN(cellFunctionForEnvironment(environment, "ccr", testCellID), color),
	}
}

func validConnectorResourceCellTarget() ConnectorResourceCellTarget {
	return connectorResourceCellTarget("blue")
}

func connectorResourceCellTarget(color string) ConnectorResourceCellTarget {
	return connectorResourceCellTargetForEnvironment(testEnvironment, color)
}

func connectorResourceCellTargetForEnvironment(environment, color string) ConnectorResourceCellTarget {
	return ConnectorResourceCellTarget{
		ResolveConnectorResourceAliasARN: aliasARN(cellFunctionForEnvironment(environment, "creso", testCellID), color),
	}
}

func hubFunction(operationSuffix string) string {
	return hubFunctionForEnvironment(testEnvironment, operationSuffix)
}

func hubFunctionForEnvironment(environment, operationSuffix string) string {
	return "layerv-nhp-" + environment + "-ca-" + operationSuffix
}

func cellFunction(operationSuffix, cellID string) string {
	return cellFunctionForEnvironment(testEnvironment, operationSuffix, cellID)
}

func cellFunctionForEnvironment(environment, operationSuffix, cellID string) string {
	return hubFunctionForEnvironment(environment, operationSuffix) + "-" + cellID
}

func aliasARN(functionName, alias string) string {
	value := "arn:aws:lambda:" + testRegion + ":" + testAccountID + ":function:" + functionName
	if alias != "" {
		value += ":" + alias
	}
	return value
}

func assertConfigError(t *testing.T, err error, field string) {
	t.Helper()
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error = %T %v, want *ConfigError", err, err)
	}
	if configErr.Field != field {
		t.Fatalf("field = %q, want %q", configErr.Field, field)
	}
}
