package connectorauthority

import (
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

var (
	accountIDPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	functionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

const authorityAliasQualifier = "active"

// Boundary pins every authority target to the expected AWS account and region.
// Target ARNs remain trusted operator configuration: validation enforces the
// boundary and exact active alias but does not infer deployment-specific
// function names.
type Boundary struct {
	AccountID string
	Region    string
}

// HubTargets contains the three exact :active alias ARNs available to a hub worker.
type HubTargets struct {
	IssueAssignmentAliasARN         string
	RefreshAssignmentAliasARN       string
	IssueCredentialRecoveryAliasARN string
}

// CellTargets contains the four exact :active alias ARNs available to one cell worker.
type CellTargets struct {
	IssueRegistrationOTPAliasARN       string
	ActivateRegistrationAliasARN       string
	CompleteRegistrationAliasARN       string
	CompleteCredentialRecoveryAliasARN string
}

// NewHubClient constructs a hub-only client with a single-attempt Lambda SDK client.
func NewHubClient(cfg aws.Config, boundary Boundary, targets HubTargets) (*HubClient, error) {
	if err := validateBoundary(cfg, boundary); err != nil {
		return nil, err
	}
	if err := validateTargets(boundary,
		targetSpec{"issue_assignment", targets.IssueAssignmentAliasARN},
		targetSpec{"refresh_assignment", targets.RefreshAssignmentAliasARN},
		targetSpec{"issue_credential_recovery", targets.IssueCredentialRecoveryAliasARN},
	); err != nil {
		return nil, err
	}

	return newHubClient(newLambdaClient(cfg), targets), nil
}

// NewCellClient constructs a cell-only client with a single-attempt Lambda SDK client.
func NewCellClient(cfg aws.Config, boundary Boundary, targets CellTargets) (*CellClient, error) {
	if err := validateBoundary(cfg, boundary); err != nil {
		return nil, err
	}
	if err := validateTargets(boundary,
		targetSpec{"issue_registration_otp", targets.IssueRegistrationOTPAliasARN},
		targetSpec{"activate_registration", targets.ActivateRegistrationAliasARN},
		targetSpec{"complete_registration", targets.CompleteRegistrationAliasARN},
		targetSpec{"complete_credential_recovery", targets.CompleteCredentialRecoveryAliasARN},
	); err != nil {
		return nil, err
	}

	return newCellClient(newLambdaClient(cfg), targets), nil
}

func newHubClient(api invokeAPI, targets HubTargets) *HubClient {
	return &HubClient{
		invoker:                 invoker{api: api},
		issueAssignment:         targets.IssueAssignmentAliasARN,
		refreshAssignment:       targets.RefreshAssignmentAliasARN,
		issueCredentialRecovery: targets.IssueCredentialRecoveryAliasARN,
	}
}

func newCellClient(api invokeAPI, targets CellTargets) *CellClient {
	return &CellClient{
		invoker:                    invoker{api: api},
		issueRegistrationOTP:       targets.IssueRegistrationOTPAliasARN,
		activateRegistration:       targets.ActivateRegistrationAliasARN,
		completeRegistration:       targets.CompleteRegistrationAliasARN,
		completeCredentialRecovery: targets.CompleteCredentialRecoveryAliasARN,
	}
}

func newLambdaClient(cfg aws.Config) *lambda.Client {
	// Endpoint and middleware overrides are intentionally discarded. Private
	// connectivity is supplied by normal Lambda DNS through a VPC interface
	// endpoint, never by a caller-controlled URL. Credentials and HTTP transport
	// remain trusted inputs from the containing server process by design. Dropping
	// APIOptions also drops inherited observability middleware; this boundary
	// favors a fixed SDK stack, and callers instrument around the typed operation.
	cfg.EndpointResolver = nil
	cfg.EndpointResolverWithOptions = nil
	cfg.BaseEndpoint = nil
	cfg.APIOptions = nil
	cfg.ServiceOptions = nil
	cfg.RetryMaxAttempts = 1
	cfg.Retryer = func() aws.Retryer { return aws.NopRetryer{} }

	return lambda.NewFromConfig(cfg, func(options *lambda.Options) {
		options.BaseEndpoint = nil
		options.EndpointResolver = nil
		options.EndpointResolverV2 = lambda.NewDefaultEndpointResolverV2()
		options.RetryMaxAttempts = 1
		options.Retryer = aws.NopRetryer{}
	})
}

func validateBoundary(cfg aws.Config, boundary Boundary) error {
	if !accountIDPattern.MatchString(boundary.AccountID) {
		return &ConfigError{Field: "account_id"}
	}
	if boundary.Region == "" {
		return &ConfigError{Field: "region"}
	}
	if cfg.Region != boundary.Region {
		return &ConfigError{Field: "sdk_region"}
	}
	return nil
}

type targetSpec struct {
	field string
	value string
}

func validateTargets(boundary Boundary, targets ...targetSpec) error {
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if !validAliasARN(target.value, boundary) {
			return &ConfigError{Field: target.field}
		}
		if _, ok := seen[target.value]; ok {
			return &ConfigError{Field: target.field}
		}
		seen[target.value] = struct{}{}
	}
	return nil
}

func validAliasARN(value string, boundary Boundary) bool {
	target, err := arn.Parse(value)
	if err != nil || target.Partition != "aws" || target.Service != "lambda" ||
		target.Region != boundary.Region || target.AccountID != boundary.AccountID {
		return false
	}

	parts := strings.Split(target.Resource, ":")
	// AWS alias qualifiers are case-sensitive; accept only the exact active alias.
	if len(parts) != 3 || parts[0] != "function" ||
		!functionNamePattern.MatchString(parts[1]) || parts[2] != authorityAliasQualifier {
		return false
	}
	return true
}
